#!/usr/bin/env python3
"""Generate dedicated new-cluster inputs, or discover an existing ACK network."""
from datetime import datetime, timezone
import argparse
import ipaddress
import os
import re
import secrets

from cloud import Client, OPERATOR, ROOT, read, require, write
from network import network_config, select_zone


def free_cidrs(vpc_cidr, switches, count):
    vpc = ipaddress.ip_network(vpc_cidr)
    occupied = [ipaddress.ip_network(s['CidrBlock']) for s in switches]
    require(vpc.version == 4 and vpc.prefixlen <= 24, 'The VPC must have room for dedicated /24 Pod/PodVM vSwitches.')
    result = []
    for subnet in vpc.subnets(new_prefix=24):
        if not any(subnet.overlaps(other) for other in occupied):
            result.append(str(subnet))
            if len(result) == count:
                return result
    require(False, 'Not enough free /24 ranges in this VPC. Provide existing dedicated vSwitch IDs or adjust the VPC network plan.')


def discover(client, args):
    if args.new:
        config = network_config(read(ROOT / 'deployment/ack/ack.example.json'), args.vpc_cidr)
        config.update(name=args.name, ack_api_access=args.ack_api_access,
                      oss_endpoint_network=args.oss_endpoint_network)
        config['zone_id'] = select_zone(client, config, args.zone)
        account = client.api('sts', 'GetCallerIdentity')['AccountId']
        if client.selection['podvm_mode'] == 'import':
            config['oss_bucket'] = args.oss_bucket or f'cos-{account}-{secrets.token_hex(6)}'
        config['service_cidr'] = next(c for c in ('172.21.0.0/20', '10.96.0.0/16', '192.168.240.0/20')
                                      if not ipaddress.ip_network(c).overlaps(ipaddress.ip_network(config['vpc_cidr'])))
        return config, {'region': client.region, 'zone_id': config['zone_id']}
    require(args.cluster_id, 'Select --new or --cluster-id.')
    cluster = client.api('cs', 'DescribeClusterDetail', ClusterId=args.cluster_id)
    require(cluster['region_id'] == client.region, 'ACK and the selected PodVM image must use the same region.')
    worker_switch = cluster['vswitch_ids'][0]
    switch = client.api('vpc', 'DescribeVSwitchAttributes', RegionId=client.region, VSwitchId=worker_switch)
    vpc_id = switch['VpcId']
    require(vpc_id == cluster['vpc_id'], 'Worker vSwitch must be in the selected ACK VPC.')
    for selected in (args.pod_vswitch_id, args.podvm_vswitch_id):
        if selected:
            detail = client.api('vpc', 'DescribeVSwitchAttributes', RegionId=client.region, VSwitchId=selected)
            require(detail['VpcId'] == vpc_id and detail['ZoneId'] == switch['ZoneId'],
                    'Selected Pod/PodVM vSwitch must be in the worker VPC and zone.')
    vpc = client.api('vpc', 'DescribeVpcAttribute', RegionId=client.region, VpcId=vpc_id)
    switches, page = [], 1
    while True:
        result = client.api('vpc', 'DescribeVSwitches', RegionId=client.region, VpcId=vpc_id, PageNumber=page, PageSize=50)
        switches.extend(result['VSwitches']['VSwitch'])
        if len(switches) >= result['TotalCount']:
            break
        page += 1
    needed = int(not args.podvm_vswitch_id)
    cidrs = iter(free_cidrs(vpc['CidrBlock'], switches, needed) if needed else [])
    config = read(ROOT / 'deployment/ack/ack.example.json')
    config.update(name=args.name, cluster_id=args.cluster_id,
                  ack_api_access=args.ack_api_access, oss_endpoint_network=args.oss_endpoint_network,
                  worker_vswitch_id=worker_switch,
                  pod_vswitch_id=args.pod_vswitch_id, podvm_vswitch_id=args.podvm_vswitch_id)
    config['pod_vswitch_cidr'] = ''
    config['podvm_vswitch_cidr'] = next(cidrs) if not args.podvm_vswitch_id else ''
    # Keep the Kubernetes service network outside the VPC address space.
    config['service_cidr'] = next(c for c in ('172.21.0.0/20', '10.96.0.0/16', '192.168.240.0/20')
                                  if not ipaddress.ip_network(c).overlaps(ipaddress.ip_network(vpc['CidrBlock'])))
    account = client.api('sts', 'GetCallerIdentity')['AccountId']
    if client.selection['podvm_mode'] == 'import':
        config['oss_bucket'] = args.oss_bucket or f'cos-{account}-{secrets.token_hex(6)}'
    return config, {'region': client.region, 'vpc_id': vpc_id, 'zone_id': switch['ZoneId']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', default='cos-' + datetime.now(timezone.utc).strftime('%Y%m%d-') + secrets.token_hex(3))
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--new', action='store_true', help='Create a dedicated VPC and vSwitches for a new ACK.')
    target.add_argument('--cluster-id', default='', help='Use the network of this existing ACK cluster.')
    for name in ('pod-vswitch-id', 'podvm-vswitch-id', 'oss-bucket'):
        parser.add_argument('--' + name, default='')
    parser.add_argument('--ack-api-access', choices=('public', 'private'), default='public')
    parser.add_argument('--oss-endpoint-network', choices=('public', 'internal'), default='public')
    parser.add_argument('--replace', action='store_true', help='Replace an input file before cloud setup has started.')
    parser.add_argument('--zone', default='', help='Optional zone; otherwise select available worker/TDX capacity.')
    parser.add_argument('--vpc-cidr', default='10.64.0.0/16', help='CIDR for the new dedicated VPC.')
    args = parser.parse_args()
    require(re.fullmatch(r'[a-z][a-z0-9-]{1,39}', args.name), 'Use a name of 2–40 lowercase letters, digits or hyphens.')
    require(not (OPERATOR / 'ack-state.json').exists(), 'Cloud setup has started; keep its inputs and state together.')
    path = OPERATOR / 'ack.json'
    require(args.replace or not path.exists(), f'{path} already exists. Review it or use --replace before setup starts.')
    config, location = discover(Client(), args)
    os.umask(0o077)
    write(path, config)
    print(f'Cloud inputs saved: {path}', flush=True)
    print(f'Deployment: {config["name"]}; region: {location["region"]}; zone: {location["zone_id"]}.', flush=True)
    if args.new:
        print(f'New dedicated VPC: {config["vpc_cidr"]}; worker/Pod/PodVM subnets: '
              f'{config["worker_vswitch_cidr"]}, {config["pod_vswitch_cidr"]}, {config["podvm_vswitch_cidr"]}.', flush=True)
    else:
        print(f'Existing ACK: {config["cluster_id"]}; VPC: {location["vpc_id"]}; worker vSwitch: {config["worker_vswitch_id"]}.', flush=True)
    if config['oss_bucket']:
        print(f'Private image-import bucket: {config["oss_bucket"]} (created by ./cos cloud image).', flush=True)


if __name__ == '__main__':
    main()
