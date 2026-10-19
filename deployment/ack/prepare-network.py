#!/usr/bin/env python3
"""Prepare the dedicated PodVM vSwitch, security group and private connectivity."""
import argparse
import ipaddress
import os

from cloud import Cloud, require


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    cloud = Cloud()
    detail = cloud.cluster()
    vpc, zone = cloud.state['vpc_id'], cloud.state['zone_id']
    host = ipaddress.ip_address(os.environ['HOST_IP'])
    require(host.version == 4 and host.is_private and not host.is_loopback, 'HOST_IP must be the service host private IPv4.')
    require(not cloud.config.get('service_host_ip') or str(host) == cloud.config['service_host_ip'],
            'HOST_IP differs from the discovered service ECS address in ack.json.')
    service_group = cloud.config['service_host_security_group_id']
    require(service_group and not service_group.startswith('YOUR_'), 'Fill in service_host_security_group_id in ack.json.')
    groups = [service_group, detail['security_group_id']]
    for group in groups:
        info = cloud.api('ecs', 'DescribeSecurityGroupAttribute', RegionId=cloud.region, SecurityGroupId=group)
        require(info['VpcId'] == vpc, 'Service host, ACK workers and PodVMs must use the same VPC.')
    cloud.switch('podvm', vpc, zone)
    group = cloud.state.get('podvm_security_group_id')
    if not group:
        response = cloud.api('ecs', 'CreateSecurityGroup', RegionId=cloud.region, VpcId=vpc,
                             SecurityGroupName=cloud.name + '-podvm', Description=cloud.name,
                             ClientToken=cloud.name + '-podvm-sg',
                             **{'Tag.1.Key': 'confidential-openshell-owner', 'Tag.1.Value': cloud.name})
        group = response['SecurityGroupId']
        cloud.save(podvm_security_group_id=group)

    def allow(target, source=None, port=None, cidr=None):
        cloud.api('ecs', 'AuthorizeSecurityGroup', RegionId=cloud.region, SecurityGroupId=target,
                  IpProtocol='tcp' if port else 'all', PortRange=f'{port}/{port}' if port else '-1/-1',
                  SourceGroupId=source, SourceCidrIp=cidr, Description=cloud.name,
                  absent='InvalidPermission.Duplicate')

    # CAA dynamically allocates tunnel endpoints. Scope mutual access to these two groups.
    allow(group, groups[1])
    allow(groups[1], group)
    allow(groups[1], port=22, cidr=str(host) + '/32')
    for source in (groups[1], group):
        for port in (5000, 8443, 9443):
            allow(service_group, source, port)
    print(f'PodVM network ready: {cloud.state["podvm_vswitch_id"]}, {group}.')


if __name__ == '__main__':
    main()
