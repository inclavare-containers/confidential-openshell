#!/usr/bin/env python3
"""Prepare PodVM networking in the ACK worker VPC and zone."""
import argparse

from cloud import Cloud, require


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    cloud = Cloud()
    detail = cloud.cluster()
    vpc, zone = cloud.state['vpc_id'], cloud.state['zone_id']
    worker_group = detail['security_group_id']
    info = cloud.api('ecs', 'DescribeSecurityGroupAttribute', RegionId=cloud.region, SecurityGroupId=worker_group)
    require(info['VpcId'] == vpc, 'Worker security group must be in the ACK VPC.')
    cloud.switch('podvm', vpc, zone)
    group = cloud.state.get('podvm_security_group_id')
    if not group:
        response = cloud.api('ecs', 'CreateSecurityGroup', RegionId=cloud.region, VpcId=vpc,
                             SecurityGroupName=cloud.name + '-podvm', Description=cloud.name,
                             ClientToken=cloud.name + '-podvm-sg',
                             **{'Tag.1.Key': 'confidential-openshell-owner', 'Tag.1.Value': cloud.name})
        group = response['SecurityGroupId']
        cloud.save(podvm_security_group_id=group)

    def allow(target, source):
        cloud.api('ecs', 'AuthorizeSecurityGroup', RegionId=cloud.region, SecurityGroupId=target,
                  IpProtocol='all', PortRange='-1/-1', SourceGroupId=source, Description=cloud.name,
                  absent='InvalidPermission.Duplicate')

    # CAA dynamically allocates tunnel endpoints. Scope mutual access to these two groups.
    allow(group, worker_group)
    allow(worker_group, group)
    print(f'PodVM network ready: {cloud.state["podvm_vswitch_id"]}, {group}.')


if __name__ == '__main__':
    main()
