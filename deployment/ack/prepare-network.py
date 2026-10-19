#!/usr/bin/env python3
"""Prepare cloud-side PodVM networking; optionally configure an ECS development host."""
import argparse
import ipaddress

from cloud import Cloud, require


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    cloud = Cloud()
    detail = cloud.cluster()
    vpc, zone = cloud.state['vpc_id'], cloud.state['zone_id']
    service_group = cloud.config['service_host_security_group_id']
    worker_group = detail['security_group_id']
    ssh_source = cloud.config['worker_ssh_source_cidr']
    if ssh_source:
        require(ipaddress.ip_network(ssh_source).version == 4, 'worker_ssh_source_cidr must be an IPv4 CIDR.')
    for group in (g for g in (service_group, worker_group) if g):
        info = cloud.api('ecs', 'DescribeSecurityGroupAttribute', RegionId=cloud.region, SecurityGroupId=group)
        require(info['VpcId'] == vpc, 'The optional service ECS group and worker group must be in the ACK VPC.')
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
    allow(group, worker_group)
    allow(worker_group, group)
    if ssh_source:
        allow(worker_group, port=22, cidr=ssh_source)
    if service_group:
        for source in (worker_group, group):
            for port in (5000, 8443, 9443):
                allow(service_group, source, port)
    print(f'PodVM network ready: {cloud.state["podvm_vswitch_id"]}, {group}.')


if __name__ == '__main__':
    main()
