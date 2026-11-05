#!/usr/bin/env python3
"""Prepare PodVM networking in the ACK worker VPC and zone."""
import argparse
import ipaddress

from cloud import Cloud, require


def inherit_worker_snat(cloud, vpc):
    worker = cloud.api('vpc', 'DescribeVSwitchAttributes', RegionId=cloud.region,
                       VSwitchId=cloud.config['worker_vswitch_id'])
    guest = cloud.api('vpc', 'DescribeVSwitchAttributes', RegionId=cloud.region,
                      VSwitchId=cloud.state['podvm_vswitch_id'])

    def pages(operation, collection, item, **parameters):
        page, count = 1, 0
        while True:
            result = cloud.api('vpc', operation, RegionId=cloud.region, PageNumber=page, PageSize=50, **parameters)
            rows = result[collection][item]
            yield from rows
            count += len(rows)
            if count >= int(result['TotalCount']):
                return
            page += 1

    entries = []
    for gateway in pages('DescribeNatGateways', 'NatGateways', 'NatGateway', VpcId=vpc):
        for table in gateway['SnatTableIds']['SnatTableId']:
            entries.extend(pages('DescribeSnatTableEntries', 'SnatTableEntries', 'SnatTableEntry', SnatTableId=table))

    def covers(entry, switch, switch_id):
        return entry.get('SourceVSwitchId') == switch_id or (
            bool(entry.get('SourceCIDR')) and
            ipaddress.ip_network(switch['CidrBlock']).subnet_of(ipaddress.ip_network(entry['SourceCIDR'])))

    existing = [e for e in entries if covers(e, guest, cloud.state['podvm_vswitch_id'])]
    if existing:
        require(len(existing) == 1, 'Multiple PodVM SNAT routes found; review the VPC route/SNAT configuration.')
        table, entry_id = existing[0]['SnatTableId'], existing[0]['SnatEntryId']
    else:
        candidates = {(e['SnatTableId'], e['SnatIp']) for e in entries
                      if e['Status'] == 'Available' and covers(e, worker, cloud.config['worker_vswitch_id'])}
        if not candidates:
            require(not cloud.state.get('created_cluster'), 'ACK worker SNAT is missing; inspect the cluster NAT gateway before continuing.')
            print('No worker SNAT to inherit. PodVMs require the routed egress configured for this existing cluster.')
            return
        require(len(candidates) == 1, 'Multiple worker SNAT routes found; review the VPC route/SNAT configuration.')
        table, address = candidates.pop()
        response = cloud.api('vpc', 'CreateSnatEntry', RegionId=cloud.region, SnatTableId=table,
                             SourceVSwitchId=cloud.state['podvm_vswitch_id'], SnatIp=address,
                             SnatEntryName=cloud.name + '-podvm', ClientToken=cloud.name + '-podvm-snat')
        entry_id = response['SnatEntryId']
    cloud.save(podvm_snat_entry_id=entry_id, podvm_snat_table_id=table)
    rows = cloud.wait('PodVM SNAT', lambda: cloud.api('vpc', 'DescribeSnatTableEntries', RegionId=cloud.region,
               SnatTableId=table, SnatEntryId=entry_id)['SnatTableEntries']['SnatTableEntry'],
               lambda rows: len(rows) == 1 and rows[0]['Status'] == 'Available', timeout=300)
    cloud.save(podvm_egress_ips=rows[0]['SnatIp'].split(','))
    print(f'PodVM outbound public IPs: {rows[0]["SnatIp"]}.', flush=True)


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
    inherit_worker_snat(cloud, vpc)
    print(f'PodVM network ready: {cloud.state["podvm_vswitch_id"]}, {group}.')
    print('Worker/PodVM tunnel access is configured between their security groups.')
    print('Trusted host ingress must allow these cloud clients on TCP 5000 (registry), 8443 (KBS), and 9443 (Gateway).')


if __name__ == '__main__':
    main()
