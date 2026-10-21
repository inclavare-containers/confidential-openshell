#!/usr/bin/env python3
"""Create/select ACK, obtain kubeconfig and check the worker profile."""
import argparse
import json
import os
import subprocess

from cloud import Cloud, OPERATOR, require, run, write
from network import create_network, require_tdx_zone


def kubectl(env, *args):
    command = ['kubectl', '--request-timeout=10s', *args]
    try:
        return run(command, env=env, capture_output=True, timeout=30).stdout
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or '').strip() or f'kubectl exited with status {exc.returncode}.'
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or ''
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors='replace')
        detail = 'kubectl did not complete within 30 seconds.\n' + stderr.strip()
    raise SystemExit(
        f'ACK Kubernetes API request failed (kubeconfig: {env["KUBECONFIG"]}):\n{detail}\n'
        'Keep ack.json and ack-state.json; repeat this step after fixing the reported '
        'connection or credential error to resume the existing cluster.'
    ) from None


def cluster_request(config, region, vpc, pod_switch):
    return {
        'name': config['name'], 'client_token': config['name'] + '-cluster',
        'cluster_type': 'ManagedKubernetes', 'profile': 'Default', 'cluster_spec': 'ack.pro.small',
        'region_id': region, 'kubernetes_version': config['kubernetes_version'],
        'vpcid': vpc, 'vswitch_ids': [config['worker_vswitch_id']],
        'pod_vswitch_ids': [pod_switch], 'service_cidr': config['service_cidr'],
        'proxy_mode': 'ipvs', 'endpoint_public_access': config['ack_api_access'] == 'public', 'snat_entry': True,
        'deletion_protection': True, 'rrsa_config': {'enabled': True},
        'addons': [
            {'name': 'terway-eniip', 'config': json.dumps({'IPVlan': 'true', 'NetworkPolicy': 'true'})},
            {'name': 'csi-plugin', 'config': ''}, {'name': 'csi-provisioner', 'config': ''},
        ],
        'tags': [{'key': 'confidential-openshell-owner', 'value': config['name']}],
    }


def nodepool_request(config, security_group, key):
    return {
        'nodepool_info': {'name': config['name'] + '-worker', 'type': 'ess'},
        'auto_scaling': {'enable': False, 'min_instances': 0, 'max_instances': config['worker_count']},
        'scaling_group': {
            'vswitch_ids': [config['worker_vswitch_id']], 'instance_types': [config['worker_instance_type']],
            'instance_charge_type': 'PostPaid', 'spot_strategy': 'NoSpot',
            'system_disk_category': 'cloud_essd', 'system_disk_size': 80,
            'image_type': 'Ubuntu', 'image_id': config['worker_image_id'],
            'security_group_ids': [security_group], 'key_pair': key,
            'desired_size': config['worker_count'], 'data_disks': [],
            'tags': [{'key': 'confidential-openshell-owner', 'value': config['name']}],
        },
        'kubernetes_config': {'runtime': 'containerd', 'runtime_version': config['containerd_version'],
                              'cms_enabled': False, 'labels': [], 'taints': []},
        'management': {'enable': False, 'auto_repair': False, 'auto_upgrade': False},
    }


def validate_nodes(nodes):
    require(nodes['items'], 'ACK has no workers. Wait for node-pool creation, then repeat this step.')
    require(len({n['metadata']['labels']['topology.kubernetes.io/zone'] for n in nodes['items']}) == 1,
            'This deployment profile requires a single worker zone.')
    for node in nodes['items']:
        status = node['status']
        require(status.get('features', {}).get('supplementalGroupsPolicy') is True and
                status['nodeInfo']['operatingSystem'] == 'linux' and status['nodeInfo']['architecture'] == 'amd64' and
                'Ubuntu 24.04' in status['nodeInfo'].get('osImage', '') and
                status['nodeInfo']['containerRuntimeVersion'].startswith('containerd://') and
                any(c['type'] == 'Ready' and c['status'] == 'True' for c in status['conditions']),
                f"Worker {node['metadata']['name']} must be Ready Ubuntu 24.04/amd64 and support containerd/supplementalGroupsPolicy.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--create', action='store_true', help='Create a paid ACK Pro cluster and workers if cluster_id is empty.')
    parser.add_argument('--enable-rrsa', action='store_true', help='Enable RRSA if it is disabled on an existing cluster.')
    args = parser.parse_args()
    cloud = Cloud()
    config = cloud.config
    if config.get('zone_id'):
        require_tdx_zone(cloud.region, config['podvm_instance_type'], config['zone_id'])
    cluster = cloud.state.get('cluster_id') or config.get('cluster_id')
    require(cluster or args.create, 'Set cluster_id in ack.json, or use --create to create a new paid cluster.')
    if not cluster:
        require(config['worker_count'] > 0, 'worker_count must be positive.')
        versions = cloud.api('cs', 'DescribeKubernetesVersionMetadata', Region=cloud.region,
                             ClusterType='ManagedKubernetes', KubernetesVersion=config['kubernetes_version'])
        version = next((v for v in versions if v['version'] == config['kubernetes_version'] and v['creatable']), None)
        require(version and any(r['name'] == 'containerd' and r['version'] == config['containerd_version']
                                for r in version['runtimes']), 'ACK does not offer the configured Kubernetes/containerd versions.')
        if not config['worker_image_id']:
            images = [i for i in version['images'] if i['image_type'] == 'Ubuntu' and
                      i['architecture'] == 'x86_64' and i['os_version'] == '24.04']
            require(images, 'ACK does not offer an Ubuntu 24.04 worker image for this version.')
            config = {**config, 'worker_image_id': images[0]['image_id']}
        cloud.save(worker_image_id=config['worker_image_id'])
        if not config['worker_vswitch_id']:
            create_network(cloud)
            config = {**config, 'worker_vswitch_id': cloud.config['worker_vswitch_id']}
        switch = cloud.api('vpc', 'DescribeVSwitchAttributes', RegionId=cloud.region,
                           VSwitchId=config['worker_vswitch_id'])
        vpc, zone = switch['VpcId'], switch['ZoneId']
        cloud.save(vpc_id=vpc, zone_id=zone)
        pod_switch = cloud.switch('pod', vpc, zone)
        request = cluster_request(config, cloud.region, vpc, pod_switch)
        write(OPERATOR / 'cluster-request.json', request)
        print(f'Creating ACK Pro cluster {cloud.name} with Terway, RRSA, public API={request["endpoint_public_access"]}…', flush=True)
        response = cloud.api('cs', 'CreateCluster', body=request)
        cluster = response['cluster_id']
        cloud.save(cluster_id=cluster, created_cluster=True)
    detail = cloud.wait('ACK control plane', lambda: cloud.api('cs', 'DescribeClusterDetail', ClusterId=cluster),
                        lambda d: d['state'] == 'running')
    require(detail['region_id'] == cloud.region, 'ACK and the selected PodVM image must be in the same region.')
    if config['ack_api_access'] == 'public':
        endpoints = detail['master_url']
        endpoints = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
        require(endpoints.get('api_server_endpoint'),
                'ACK public API is disabled. Enable it in ACK console > Cluster Information, or select private API with routed connectivity.')
    cloud.save(cluster_id=cluster)
    if not detail.get('rrsa_config', {}).get('enabled') and args.enable_rrsa:
        cloud.api('cs', 'ModifyCluster', ClusterId=cluster, body={'enable_rrsa': True})
        detail = cloud.wait('ACK RRSA', cloud.cluster, lambda d: d['state'] == 'running' and
                            d.get('rrsa_config', {}).get('enabled') is True)
    require(detail.get('rrsa_config', {}).get('enabled') is True,
            'RRSA is disabled. Repeat this step with --enable-rrsa to enable it.')
    cloud.save(vpc_id=detail['vpc_id'], worker_security_group_id=detail['security_group_id'],
               rrsa=detail['rrsa_config'])
    if cloud.state.get('created_cluster') and not cloud.state.get('nodepool_id'):
        config = {**config, 'worker_image_id': cloud.state['worker_image_id']}
        key = OPERATOR / 'worker-key'
        if not key.exists():
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
        cloud.api('ecs', 'ImportKeyPair', RegionId=cloud.region, KeyPairName=cloud.name + '-worker',
                  PublicKeyBody=key.with_suffix('.pub').read_text().strip(), absent='InvalidKeyPair.Duplicate')
        request = nodepool_request(config, detail['security_group_id'], cloud.name + '-worker')
        write(OPERATOR / 'nodepool-request.json', request)
        # ACK node-pool creation has no idempotency token; discover by the owned name on retries.
        pools = cloud.api('cs', 'DescribeClusterNodePools', ClusterId=cluster)['nodepools']
        matches = [p for p in pools if p['nodepool_info']['name'] == cloud.name + '-worker']
        require(len(matches) <= 1, 'Multiple matching worker node pools; inspect ACK before continuing.')
        pool = matches[0]['nodepool_info']['nodepool_id'] if matches else cloud.api(
            'cs', 'CreateClusterNodePool', ClusterId=cluster, body=request)['nodepool_id']
        cloud.save(nodepool_id=pool)
    kubeconfig = cloud.api('cs', 'DescribeClusterUserKubeconfig', ClusterId=cluster,
                          PrivateIpAddress=config['ack_api_access'] == 'private', TemporaryDurationMinutes=4320)
    path = OPERATOR / 'administrator-kubeconfig'
    write(path, kubeconfig['config'])
    env = {**os.environ, 'KUBECONFIG': str(path)}
    nodes = cloud.wait('Ready ACK workers', lambda: json.loads(kubectl(env, 'get', 'nodes', '-o', 'json')),
               lambda d: bool(d['items']) and all(any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in n['status'].get('conditions', [])) for n in d['items']))
    validate_nodes(nodes)
    require_tdx_zone(cloud.region, config['podvm_instance_type'],
                     nodes['items'][0]['metadata']['labels']['topology.kubernetes.io/zone'])
    network = json.loads(kubectl(env, '-n', 'kube-system', 'get', 'configmap', 'eni-config', '-o', 'json'))
    eni = json.loads(network['data']['eni_conf'])
    require(str(eni.get('disable_network_policy', False)).lower() == 'false',
            'Terway NetworkPolicy is disabled. See deployment/ack/README.md.')
    classes = json.loads(kubectl(env, 'get', 'storageclass', '-o', 'json'))
    require(any(c['metadata']['name'] == config['csi_storage_class'] for c in classes['items']),
            f'Host StorageClass {config["csi_storage_class"]} is missing. Enable the ACK csi-plugin and csi-provisioner storage add-ons before attachment.')
    cloud.save(zone_id=nodes['items'][0]['metadata']['labels']['topology.kubernetes.io/zone'])
    print(kubectl(env, 'get', 'nodes', '-o', 'wide'), end='')
    print(f'ACK ready: {cluster} ({config["ack_api_access"]} API). Kubeconfig is valid for up to 3 days; repeat to renew it.')
    print(f'VPC: {cloud.state["vpc_id"]}; worker vSwitch: {config["worker_vswitch_id"]}; worker security group: {cloud.state["worker_security_group_id"]}.')


if __name__ == '__main__':
    main()
