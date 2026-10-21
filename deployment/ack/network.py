"""Create the dedicated network for a new ACK; existing clusters retain their VPC."""
import ipaddress

from cloud import require


# TDX availability is narrower than ordinary ECS inventory. Published support:
# https://help.aliyun.com/zh/ecs/user-guide/build-a-tdx-confidential-computing-environment
TDX_FAMILIES = {
    'cn-beijing': {
        'cn-beijing-i': ('ecs.g8i', 'ecs.g9i', 'ecs.c9i', 'ecs.r9i', 'ecs.ebmg8i'),
        'cn-beijing-l': ('ecs.g8i',),
    },
    'cn-hangzhou': {'cn-hangzhou-j': ('ecs.r9i',)},
    'cn-hongkong': {zone: ('ecs.g8i',) for zone in ('cn-hongkong-b', 'cn-hongkong-c', 'cn-hongkong-d')},
    'ap-southeast-1': {'ap-southeast-1b': ('ecs.g8i',)},
}


def tdx_zones(region, instance_type):
    family = instance_type.rsplit('.', 1)[0]
    return {zone for zone, families in TDX_FAMILIES.get(region, {}).items() if family in families}


def require_tdx_zone(region, instance_type, zone):
    supported = tdx_zones(region, instance_type)
    require(zone in supported,
            f'{zone} does not support the configured TDX profile ({instance_type}). '
            f'Supported zones: {", ".join(sorted(supported)) or "none in this region"}. '
            'Ordinary ECS inventory does not imply TDX support. Keep existing deployment state; '
            'select a supported zone for a new deployment.')


def select_zone(client, config, requested=''):
    candidates = tdx_zones(client.region, config['podvm_instance_type'])
    require(candidates, f'No documented TDX placement for {config["podvm_instance_type"]} in {client.region}.')
    if requested:
        require_tdx_zone(client.region, config['podvm_instance_type'], requested)
    for instance_type in sorted({config['worker_instance_type'], config['podvm_instance_type']}):
        response = client.api('ecs', 'DescribeAvailableResource', RegionId=client.region,
                              DestinationResource='InstanceType', InstanceType=instance_type,
                              InstanceChargeType='PostPaid', IoOptimized='optimized')
        available = set()
        for zone in response['AvailableZones']['AvailableZone']:
            for resource in zone.get('AvailableResources', {}).get('AvailableResource', []):
                if resource['Type'] != 'InstanceType':
                    continue
                if any(r['Value'] == instance_type and r['Status'] == 'Available'
                       for r in resource.get('SupportedResources', {}).get('SupportedResource', [])):
                    available.add(zone['ZoneId'])
        candidates &= available
    require(candidates, 'No zone currently has both worker and TDX PodVM capacity. Retry later or select another region before packaging.')
    require(not requested or requested in candidates,
            f'{requested} has no matching capacity. Available zones: {", ".join(sorted(candidates))}.')
    selected = requested or sorted(candidates)[0]
    print(f'TDX placement: {selected}, {config["podvm_instance_type"]}; worker inventory is available.', flush=True)
    return selected


def network_config(config, cidr):
    vpc = ipaddress.ip_network(cidr)
    require(vpc.version == 4 and vpc.prefixlen <= 22 and vpc.is_private,
            'Use a private IPv4 VPC CIDR of /22 or larger, with room for three /24 vSwitches.')
    worker, pod, podvm = list(vpc.subnets(new_prefix=24))[:3]
    return {**config, 'vpc_cidr': str(vpc), 'worker_vswitch_cidr': str(worker),
            'pod_vswitch_cidr': str(pod), 'podvm_vswitch_cidr': str(podvm)}


def create_network(cloud):
    config = cloud.config
    vpc = cloud.state.get('vpc_id')
    if not vpc:
        print(f'Creating dedicated VPC {config["vpc_cidr"]} in {cloud.region}…', flush=True)
        result = cloud.api('vpc', 'CreateVpc', RegionId=cloud.region, VpcName=cloud.name,
                           CidrBlock=config['vpc_cidr'], ClientToken=cloud.name + '-vpc',
                           **{'Tag.1.Key': 'confidential-openshell-owner', 'Tag.1.Value': cloud.name})
        vpc = result['VpcId']
        cloud.save(vpc_id=vpc, zone_id=config['zone_id'], created_vpc=True)
    cloud.wait('VPC ' + vpc,
               lambda: cloud.api('vpc', 'DescribeVpcAttribute', RegionId=cloud.region, VpcId=vpc),
               lambda row: row['Status'] == 'Available')
    worker = cloud.switch('worker', vpc, cloud.state['zone_id'])
    cloud.config['worker_vswitch_id'] = worker
    print(f'Dedicated network ready: VPC {vpc}; worker vSwitch {worker}; zone {cloud.state["zone_id"]}.', flush=True)
    return worker
