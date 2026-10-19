#!/usr/bin/env python3
"""Discover the service ECS network and generate reviewable ACK inputs without creating cloud resources."""
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
    require(args.service_host_instance_id or host_ip, 'Set HOST_IP to the service ECS private IPv4, or pass --service-host-instance-id.')
    query = {'InstanceIds': json.dumps([args.service_host_instance_id])} if args.service_host_instance_id else {
        'InstanceNetworkType': 'vpc', 'PrivateIpAddresses': json.dumps([host_ip]),
    }
    hosts = client.api('ecs', 'DescribeInstances', RegionId=client.region, **query)['Instances']['Instance']
    require(len(hosts) == 1, 'Cannot uniquely find the service ECS. Check the account/region or pass --service-host-instance-id.')
    host = hosts[0]
    private_ips = host['VpcAttributes']['PrivateIpAddress']['IpAddress']
    require(not host_ip or host_ip in private_ips, 'HOST_IP does not belong to the selected service ECS.')
    host_ip = host_ip or private_ips[0]
    groups = host['SecurityGroupIds']['SecurityGroupId']
    group = args.service_host_security_group_id
    require(group or len(groups) == 1,
            'Service ECS has multiple security groups: ' + ', '.join(groups) + '. Select one with --service-host-security-group-id.')
    group = group or groups[0]
    require(group in groups, 'The selected security group is not attached to the service ECS.')
    vpc_id = host['VpcAttributes']['VpcId']
    worker_switch = args.worker_vswitch_id or host['VpcAttributes']['VSwitchId']
    if args.cluster_id:
        cluster = client.api('cs', 'DescribeClusterDetail', ClusterId=args.cluster_id)
        require(cluster['region_id'] == client.region and cluster['vpc_id'] == vpc_id,
                'Existing ACK and the service ECS must use the same region and VPC.')
        worker_switch = args.worker_vswitch_id or cluster['vswitch_ids'][0]
    switch = client.api('vpc', 'DescribeVSwitchAttributes', RegionId=client.region, VSwitchId=worker_switch)
    require(switch['VpcId'] == vpc_id, 'Worker vSwitch must be in the service ECS VPC.')
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
    config.update(name=args.name, cluster_id=args.cluster_id, service_host_instance_id=host['InstanceId'],
                  service_host_ip=host_ip, service_host_security_group_id=group, worker_vswitch_id=worker_switch,
                  pod_vswitch_id=args.pod_vswitch_id, podvm_vswitch_id=args.podvm_vswitch_id)
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
