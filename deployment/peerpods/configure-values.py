#!/usr/bin/env python3
"""Generate private PeerPods/CSI values from the completed cloud steps and published images."""
import argparse
import base64
import gzip
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ack'))
from cloud import Cloud, OPERATOR, ROOT, require, write

INITDATA = Path('/etc/openshell-confidential/guest-initdata-base.toml')


def main():
    parser = argparse.ArgumentParser(prog='./cos cluster values', description=__doc__)
    parser.add_argument('--replace', action='store_true', help='Replace previously generated values after reviewing input changes.')
    args = parser.parse_args()
    cloud = Cloud()
    state = cloud.state
    for key in ('cluster_id', 'podvm_image_id', 'podvm_vswitch_id', 'podvm_security_group_id', 'ram_roles'):
        require(state.get(key), f'Missing {key}; complete deployment step 3 first.')
    paths = [OPERATOR / (name + '-values.yaml') for name in ('peerpods', 'csi')]
    require(args.replace or not any(p.exists() for p in paths),
            'Values already exist. Review them, then use --replace to regenerate.')

    def image(name):
        value = (OPERATOR / (name + '-image.txt')).read_text().strip()
        require('@sha256:' in value, f'{name} must have a published digest from step 6.')
        return value

    def split(name):
        repository, digest = image(name).split('@')
        return repository, 'locked@' + digest

    peer = yaml.safe_load((ROOT / 'deployment/peerpods/peerpods-values.example.yaml').read_text())
    peer['image']['name'], peer['image']['tag'] = split('cloud-api-adaptor')
    peer['alibabacloud']['rrsa']['roleArn'] = state['ram_roles']['caa']
    for workload in ('daemonset', 'resourceCtrl'):
        peer[workload]['serviceAccount']['annotations']['pod-identity.alibabacloud.com/role-name'] = cloud.name + '-caa'
    peer['providerConfigs']['alibabacloud'].update(
        ALIBABA_CLOUD_ROLE_ARN=state['ram_roles']['caa'], ALIBABA_CLOUD_OIDC_PROVIDER_ARN=state['rrsa']['oidc_arn'],
        IMAGEID=state['podvm_image_id'],
        INITDATA=base64.b64encode(gzip.compress(INITDATA.read_bytes(), mtime=0)).decode(),
        PAUSE_IMAGE=image('pause'), REGION=cloud.region,
        VSWITCH_ID=state['podvm_vswitch_id'], SECURITY_GROUP_IDS=state['podvm_security_group_id'],
        PODVM_INSTANCE_TYPE=cloud.config['podvm_instance_type'],
        TAGS=f'ClusterId={state["cluster_id"]},caa-csi-driver=caa-csi-block-driver',
    )
    peer['resourceCtrl']['image']['repository'], peer['resourceCtrl']['image']['tag'] = split('peerpod-ctrl')
    peer['webhook']['image']['repository'], peer['webhook']['image']['tag'] = split('peerpod_webhook')
    peer['kata-deploy']['image']['reference'] = image('kata_deploy')
    peer['kata-deploy']['kubectlImage'] = {'reference': image('kata_kubectl'), 'tag': ''}
    peer['kata-deploy']['containerd']['userDropIn'] = (
        '[plugins."io.containerd.cri.v1.images".pinned_images]\n'
        f'sandbox = "{image("pause")}"\n')
    csi = yaml.safe_load((ROOT / 'deployment/peerpods/csi-values.example.yaml').read_text())
    csi['image']['repository'], csi['image']['tag'] = split('caa-csi-block-driver')
    csi['sidecarImages'].update(provisioner=image('csi_provisioner'), nodeDriverRegistrar=image('csi_node_registrar'))
    csi['alibabacloud'].update(region=cloud.region, zoneId=state['zone_id'], clusterId=state['cluster_id'])
    csi['alibabacloud']['rrsa'].update(roleArn=state['ram_roles']['csi'], oidcProviderArn=state['rrsa']['oidc_arn'])
    for path, values in zip(paths, (peer, csi)):
        write(path, yaml.safe_dump(values, sort_keys=False))
        print(f'Generated {path}; review before installing.')
    print(f'Using cluster {state["cluster_id"]}, guest image {state["podvm_image_id"]}, PodVM vSwitch {state["podvm_vswitch_id"]}.')
    print('Runtime images use published digests; CSI uses the combined DaemonSet and cloud volume recovery.')


if __name__ == '__main__':
    main()
