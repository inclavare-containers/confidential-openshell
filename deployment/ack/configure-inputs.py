#!/usr/bin/env python3
"""Discover ACK network inputs; an ECS development host is an optional shortcut."""
from datetime import datetime, timezone
import argparse
import ipaddress
import json
import os
import re
import secrets

from cloud import Client, OPERATOR, ROOT, read, require, write


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
    host_ip = os.environ.get('HOST_IP', '')
    group = args.service_host_security_group_id
    host = None
    worker_switch = args.worker_vswitch_id
    if args.service_host_instance_id:
        hosts = client.api('ecs', 'DescribeInstances', RegionId=client.region,
                           InstanceIds=json.dumps([args.service_host_instance_id]))['Instances']['Instance']
        require(len(hosts) == 1, 'Cannot find the selected ECS development host.')
        host = hosts[0]
        host_ip = host_ip or host['VpcAttributes']['PrivateIpAddress']['IpAddress'][0]
        groups = host['SecurityGroupIds']['SecurityGroupId']
        require(group or len(groups) == 1, 'Development ECS has multiple security groups: ' + ', '.join(groups) +
                '. Choose one with --service-host-security-group-id.')
        group = group or groups[0]
        require(group in groups, 'The selected security group is not attached to the development ECS.')
        worker_switch = worker_switch or host['VpcAttributes']['VSwitchId']
    require(not group or host, '--service-host-security-group-id is only for the optional ECS development host.')
    if args.cluster_id:
        cluster = client.api('cs', 'DescribeClusterDetail', ClusterId=args.cluster_id)
        require(cluster['region_id'] == client.region, 'ACK and the selected PodVM image must use the same region.')
        worker_switch = args.worker_vswitch_id or cluster['vswitch_ids'][0]
    require(worker_switch, 'For a new ACK, pass --worker-vswitch-id. See deployment/ack/README.md to list or create cloud networks.')
    switch = client.api('vpc', 'DescribeVSwitchAttributes', RegionId=client.region, VSwitchId=worker_switch)
    vpc_id = switch['VpcId']
    if args.cluster_id:
        require(vpc_id == cluster['vpc_id'], 'Worker vSwitch must be in the selected ACK VPC.')
    if host:
        require(host['VpcAttributes']['VpcId'] == vpc_id,
                'The optional ECS development shortcut requires its host in the ACK VPC. Omit it for an external trusted host.')
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
    needed = int(not args.cluster_id and not args.pod_vswitch_id) + int(not args.podvm_vswitch_id)
    cidrs = iter(free_cidrs(vpc['CidrBlock'], switches, needed) if needed else [])
    config = read(ROOT / 'deployment/ack/ack.example.json')
    config.update(name=args.name, cluster_id=args.cluster_id,
                  ack_api_access=args.ack_api_access, oss_endpoint_network=args.oss_endpoint_network,
                  service_host_instance_id=host['InstanceId'] if host else '',
                  service_host_ip=host_ip, service_host_security_group_id=group, worker_vswitch_id=worker_switch,
                  pod_vswitch_id=args.pod_vswitch_id, podvm_vswitch_id=args.podvm_vswitch_id)
    if host:
        config['worker_ssh_source_cidr'] = host['VpcAttributes']['PrivateIpAddress']['IpAddress'][0] + '/32'
    config['pod_vswitch_cidr'] = next(cidrs) if not args.cluster_id and not args.pod_vswitch_id else ''
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
    for name in ('cluster-id', 'service-host-instance-id', 'service-host-security-group-id',
                 'worker-vswitch-id', 'pod-vswitch-id', 'podvm-vswitch-id', 'oss-bucket'):
        parser.add_argument('--' + name, default='')
    parser.add_argument('--ack-api-access', choices=('public', 'private'), default='public')
    parser.add_argument('--oss-endpoint-network', choices=('public', 'internal'), default='public')
    parser.add_argument('--replace', action='store_true', help='Replace an input file before cloud setup has started.')
    args = parser.parse_args()
    require(re.fullmatch(r'[a-z][a-z0-9-]{1,39}', args.name), 'Use a name of 2–40 lowercase letters, digits or hyphens.')
    require(not (OPERATOR / 'ack-state.json').exists(), 'Cloud setup has started; keep its inputs and state together.')
    path = OPERATOR / 'ack.json'
    require(args.replace or not path.exists(), f'{path} already exists. Review it or use --replace before setup starts.')
    config, location = discover(Client(), args)
    os.umask(0o077)
    write(path, config)
    print(json.dumps({**location, **config}, indent=2))
    print(f'Inputs saved to {path}. Discovery only: no cloud resources were created.')


if __name__ == '__main__':
    main()
