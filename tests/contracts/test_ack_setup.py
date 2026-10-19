"""Exercise cloud step boundaries, resume behavior and the saved Helm handoff offline."""
import base64
from copy import deepcopy
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deployment/ack'))
import cloud


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cluster = load('ack_cluster', 'deployment/ack/prepare-cluster.py')
network = load('ack_network', 'deployment/ack/prepare-network.py')
image = load('ack_image', 'deployment/ack/prepare-image.py')
identity = load('ack_identity', 'deployment/ack/configure-identities.py')
values = load('ack_values', 'deployment/peerpods/configure-values.py')
inputs = load('ack_inputs', 'deployment/ack/configure-inputs.py')
storage = load('ack_storage', 'deployment/ack/prepare-storage.py')


class CloudFixture:
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.operator = Path(temp.name) / 'operator'
        self.handoff = Path(temp.name) / 'handoff'
        self.operator.mkdir()
        (self.handoff / 'outputs').mkdir(parents=True)
        self.config = cloud.read(ROOT / 'deployment/ack/ack.example.json')
        self.config.update(cluster_id='c-test', worker_vswitch_id='vsw-worker',
                           oss_bucket='private-test', ack_api_access='private')
        self.selection = {'podvm_region': 'cn-beijing', 'podvm_mode': 'existing',
                          'podvm_image_id': 'm-test', 'references': 'refs.json', 'guest': None}
        cloud.write(self.handoff / 'outputs/refs.json', {'tdx.mr_td': ['approved']})
        self.inputs()
        self.detail = {'cluster_id': 'c-test', 'region_id': 'cn-beijing', 'state': 'running',
                       'vpc_id': 'vpc-test', 'security_group_id': 'sg-workers',
                       'master_url': {'api_server_endpoint': 'https://203.0.113.20:6443',
                                      'intranet_api_server_endpoint': 'https://192.168.1.20:6443'},
                       'rrsa_config': {'enabled': True, 'oidc_arn': 'acs:ram::123:oidc-provider/test',
                                       'issuer': 'https://issuer.example,https://kubernetes.default.svc'}}
        self.nodes = {'items': [{'metadata': {'name': 'worker', 'labels': {'topology.kubernetes.io/zone': 'cn-beijing-i'}},
                                'status': {'features': {'supplementalGroupsPolicy': True},
                                           'nodeInfo': {'containerRuntimeVersion': 'containerd://2.3.4',
                                                        'operatingSystem': 'linux', 'architecture': 'amd64'},
                                           'conditions': [{'type': 'Ready', 'status': 'True'}]}}]}
        self.ecs_image = {'Status': 'Available', 'OSType': 'linux', 'Architecture': 'x86_64',
                          'BootMode': 'UEFI', 'Features': {'NvmeSupport': 'supported'}}
        self.calls = []
        self.roles, self.policies, self.attachments = {}, {}, {}
        self.disabled_network_policy = False
        self.snat_entries = [{'SourceVSwitchId': 'vsw-worker', 'SourceCIDR': '192.168.16.0/20',
                              'SnatTableId': 'stb-test', 'SnatIp': '203.0.113.1',
                              'SnatEntryId': 'snat-worker', 'Status': 'Available'}]
        for module in (cloud, cluster, network, image, identity, values, inputs, storage):
            for name, value in (('OPERATOR', self.operator), ('HANDOFF', self.handoff)):
                if hasattr(module, name):
                    replacement = patch.object(module, name, value)
                    replacement.start()
                    self.addCleanup(replacement.stop)
        replacement = patch.object(cloud.Cloud, 'api', self.api)
        replacement.start()
        self.addCleanup(replacement.stop)

    def inputs(self):
        cloud.write(self.operator / 'ack.json', self.config)
        cloud.write(self.handoff / 'selection.json', self.selection)
        self.checksums()

    def checksums(self):
        paths = [p for p in self.handoff.rglob('*') if p.is_file() and p.name != 'SHA256SUMS']
        cloud.write(self.handoff / 'SHA256SUMS', ''.join(f'{cloud.sha256(p)}  {p.relative_to(self.handoff)}\n' for p in paths))

    def api(self, product, operation, **args):
        self.calls.append((operation, args))
        if operation == 'DescribeClusterDetail':
            return deepcopy(self.detail)
        if operation == 'ModifyCluster':
            self.detail['rrsa_config']['enabled'] = args['body']['enable_rrsa']
            return {}
        if operation == 'DescribeKubernetesVersionMetadata':
            return [{'version': self.config['kubernetes_version'], 'creatable': True,
                     'runtimes': [{'name': 'containerd', 'version': self.config['containerd_version']}],
                     'images': [{'image_type': 'Ubuntu', 'architecture': 'x86_64', 'os_version': '24.04', 'image_id': 'ubuntu-ack'}]}]
        if operation == 'DescribeVSwitchAttributes':
            return {'VpcId': 'vpc-test', 'ZoneId': 'cn-beijing-i', 'Status': 'Available',
                    'CidrBlock': '192.168.48.0/24' if args['VSwitchId'] == 'vsw-podvm' else '192.168.16.0/20'}
        if operation == 'DescribeNatGateways':
            return {'TotalCount': 1, 'NatGateways': {'NatGateway': [{'SnatTableIds': {'SnatTableId': ['stb-test']}}]}}
        if operation == 'DescribeSnatTableEntries':
            rows = [e for e in self.snat_entries if not args.get('SnatEntryId') or e['SnatEntryId'] == args['SnatEntryId']]
            return {'TotalCount': len(rows), 'SnatTableEntries': {'SnatTableEntry': deepcopy(rows)}}
        if operation == 'CreateSnatEntry':
            self.snat_entries.append({'SourceVSwitchId': args['SourceVSwitchId'], 'SourceCIDR': '192.168.48.0/24',
                                      'SnatTableId': args['SnatTableId'], 'SnatIp': args['SnatIp'],
                                      'SnatEntryId': 'snat-podvm', 'Status': 'Available'})
            return {'SnatEntryId': 'snat-podvm'}
        if operation == 'CreateVSwitch':
            return {'VSwitchId': 'vsw-podvm' if args['VSwitchName'].endswith('podvm') else 'vsw-pod'}
        if operation == 'CreateCluster':
            return {'cluster_id': 'c-test'}
        if operation == 'DescribeClusterNodePools':
            return {'nodepools': []}
        if operation == 'CreateClusterNodePool':
            return {'nodepool_id': 'np-test'}
        if operation == 'DescribeClusterUserKubeconfig':
            return {'config': 'private kubeconfig fixture\n'}
        if operation == 'DescribeSecurityGroupAttribute':
            return {'VpcId': 'vpc-test'}
        if operation == 'CreateSecurityGroup':
            return {'SecurityGroupId': 'sg-podvm'}
        if operation in ('ImportKeyPair', 'AuthorizeSecurityGroup'):
            return {}
        if operation == 'DescribeImages':
            return {'Images': {'Image': [deepcopy(self.ecs_image)]}}
        if operation == 'ImportImage':
            return {'ImageId': 'm-imported'}
        if operation == 'GetCallerIdentity':
            return {'AccountId': '123'}
        if operation == 'GetRole':
            return self.roles.get(args['RoleName'])
        if operation == 'CreateRole':
            role = {'Role': {'Arn': 'acs:ram::123:role/' + args['RoleName'],
                             'Description': args['Description'], 'AssumeRolePolicyDocument': args['AssumeRolePolicyDocument']}}
            self.roles[args['RoleName']] = role
            return role
        if operation == 'GetPolicy':
            return self.policies.get(args['PolicyName'])
        if operation == 'CreatePolicy':
            self.policies[args['PolicyName']] = {'Policy': {'Description': args['Description'], 'DefaultVersion': 'v1'},
                                                'document': args['PolicyDocument']}
            return {}
        if operation == 'GetPolicyVersion':
            return {'PolicyVersion': {'PolicyDocument': self.policies[args['PolicyName']]['document']}}
        if operation == 'ListPoliciesForRole':
            return {'Policies': {'Policy': self.attachments.get(args['RoleName'], [])}}
        if operation == 'AttachPolicyToRole':
            self.attachments[args['RoleName']] = [{'PolicyName': args['PolicyName'], 'PolicyType': args['PolicyType']}]
            return {}
        self.fail(f'Unexpected cloud mutation/query: {product} {operation}')

    def kubectl(self, args, **kwargs):
        if 'configmap' in args:
            data = {'data': {'eni_conf': json.dumps({'disable_network_policy': self.disabled_network_policy})}}
        else:
            data = self.nodes
        return subprocess.CompletedProcess(args, 0, json.dumps(data), '')

    def prepare(self, *args, runner=None):
        with patch.object(sys, 'argv', ['prepare-cluster.py', *args]), patch.object(cluster, 'run', runner or self.kubectl):
            cluster.main()

    def state(self):
        return cloud.read(self.operator / 'ack-state.json')

class Setup(CloudFixture, unittest.TestCase):
    def test_cli_keeps_negative_values_attached_to_their_parameter(self):
        client = cloud.Client()
        result = subprocess.CompletedProcess([], 0, '{}', '')
        with patch.object(cloud.subprocess, 'run', return_value=result) as command:
            client.api('ecs', 'AuthorizeSecurityGroup', IpProtocol='all', PortRange='-1/-1',
                       SourceGroupId='sg-workers', DryRun=True, Optional=None)
        arguments = command.call_args.args[0]
        self.assertIn('--PortRange=-1/-1', arguments)
        self.assertIn('--SourceGroupId=sg-workers', arguments)
        self.assertIn('--DryRun=true', arguments)
        self.assertFalse(any(a.startswith('--Optional') for a in arguments))

    def test_existing_cluster_only_reads_and_renews_private_kubeconfig(self):
        self.prepare()
        self.prepare()
        self.assertFalse(any(op.startswith(('Create', 'Import', 'Modify')) for op, _ in self.calls))
        self.assertEqual((self.operator / 'administrator-kubeconfig').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state()['rrsa']['oidc_arn'], self.detail['rrsa_config']['oidc_arn'])

    def test_external_trusted_host_selects_public_ack_api_without_cloud_host_identity(self):
        self.config['ack_api_access'] = 'public'
        self.inputs()
        self.prepare()
        requests = [a for op, a in self.calls if op == 'DescribeClusterUserKubeconfig']
        self.assertFalse(requests[0]['PrivateIpAddress'])
        self.assertTrue(cluster.cluster_request(self.config, 'cn-beijing', 'vpc-test', 'vsw-pod')['endpoint_public_access'])
        with patch.object(sys, 'argv', ['prepare-network.py']):
            network.main()
        rules = [a for op, a in self.calls if op == 'AuthorizeSecurityGroup']
        self.assertEqual({a['SecurityGroupId'] for a in rules}, {'sg-workers', 'sg-podvm'})
        self.assertFalse(any(a.get('SourceCidrIp') for a in rules))

    def test_podvm_snat_reuses_worker_gateway_and_survives_retries(self):
        current = cloud.Cloud()
        current.save(podvm_vswitch_id='vsw-podvm')
        network.inherit_worker_snat(current, 'vpc-test')
        network.inherit_worker_snat(current, 'vpc-test')
        requests = [a for op, a in self.calls if op == 'CreateSnatEntry']
        self.assertEqual(len(requests), 1)
        self.assertEqual((requests[0]['SnatTableId'], requests[0]['SnatIp'], requests[0]['SourceVSwitchId']),
                         ('stb-test', '203.0.113.1', 'vsw-podvm'))
        self.assertEqual(self.state()['podvm_snat_entry_id'], 'snat-podvm')

    def test_existing_vpc_snat_is_reused_without_narrowing_or_duplicate_creation(self):
        current = cloud.Cloud()
        current.save(podvm_vswitch_id='vsw-podvm')
        self.snat_entries[0].update(SourceCIDR='192.168.0.0/16', SourceVSwitchId='')
        network.inherit_worker_snat(current, 'vpc-test')
        self.assertNotIn('CreateSnatEntry', [op for op, _ in self.calls])
        self.assertEqual(self.state()['podvm_snat_entry_id'], 'snat-worker')

    def test_missing_or_ambiguous_worker_snat_fails_for_a_new_cluster(self):
        current = cloud.Cloud()
        current.save(podvm_vswitch_id='vsw-podvm', created_cluster=True)
        saved = deepcopy(self.snat_entries)
        self.snat_entries = []
        with self.assertRaisesRegex(SystemExit, 'worker SNAT is missing'):
            network.inherit_worker_snat(current, 'vpc-test')
        self.snat_entries = [saved[0], {**saved[0], 'SnatIp': '203.0.113.2'}]
        with self.assertRaisesRegex(SystemExit, 'Multiple worker SNAT routes'):
            network.inherit_worker_snat(current, 'vpc-test')
        self.assertNotIn('CreateSnatEntry', [op for op, _ in self.calls])

    def test_missing_public_api_fails_before_freezing_existing_cluster_inputs(self):
        self.config['ack_api_access'] = 'public'
        self.detail['master_url']['api_server_endpoint'] = ''
        self.inputs()
        with self.assertRaisesRegex(SystemExit, 'public API is disabled'):
            self.prepare()
        self.assertFalse((self.operator / 'ack-state.json').exists())

    def test_new_cluster_explicit_creation_and_resuming_does_not_duplicate(self):
        self.config['cluster_id'] = ''
        self.inputs()
        with self.assertRaisesRegex(SystemExit, '--create'):
            self.prepare()
        self.assertEqual(self.calls, [])
        cloud.write(self.operator / 'worker-key', 'private key fixture')
        cloud.write(self.operator / 'worker-key.pub', 'public key fixture')
        def blocked_api(args, **kwargs):
            raise subprocess.CalledProcessError(1, args, stderr='Unable to connect to the server: context deadline exceeded')
        with self.assertRaisesRegex(SystemExit, 'context deadline exceeded'):
            self.prepare('--create', runner=blocked_api)
        self.assertEqual(self.state()['nodepool_id'], 'np-test')
        self.prepare('--create')
        creates = [args['body'] for op, args in self.calls if op == 'CreateCluster']
        self.assertEqual(len(creates), 1)
        self.assertFalse(creates[0]['endpoint_public_access'])
        self.assertTrue(creates[0]['rrsa_config']['enabled'])
        self.assertTrue(json.loads(creates[0]['addons'][0]['config'])['NetworkPolicy'] == 'true')
        pools = [args['body'] for op, args in self.calls if op == 'CreateClusterNodePool']
        self.assertEqual(len(pools), 1)
        self.assertEqual(pools[0]['scaling_group']['image_id'], 'ubuntu-ack')

    def test_kubectl_deadline_is_bounded_and_reports_how_to_resume(self):
        env = {'KUBECONFIG': str(self.operator / 'administrator-kubeconfig')}
        error = subprocess.TimeoutExpired(['kubectl'], 30, stderr=b'dial tcp: i/o timeout')
        with patch.object(cluster, 'run', side_effect=error) as command:
            with self.assertRaisesRegex(SystemExit, 'within 30 seconds') as failure:
                cluster.kubectl(env, 'get', 'nodes', '-o', 'json')
        self.assertIn('ack-state.json', str(failure.exception))
        self.assertIn('dial tcp: i/o timeout', str(failure.exception))
        self.assertEqual(command.call_args.kwargs['timeout'], 30)
        self.assertIn('--request-timeout=10s', command.call_args.args[0])

    def test_rrsa_enable_requires_explicit_flag(self):
        self.detail['rrsa_config']['enabled'] = False
        with self.assertRaisesRegex(SystemExit, '--enable-rrsa'):
            self.prepare()
        self.assertNotIn('ModifyCluster', [op for op, _ in self.calls])
        self.prepare('--enable-rrsa')
        self.assertEqual([a['body'] for op, a in self.calls if op == 'ModifyCluster'], [{'enable_rrsa': True}])

    def test_unsupported_worker_and_disabled_network_policy_fail(self):
        self.nodes['items'][0]['status']['features']['supplementalGroupsPolicy'] = False
        with self.assertRaisesRegex(SystemExit, 'supplementalGroupsPolicy'):
            self.prepare()
        self.nodes['items'][0]['status']['features']['supplementalGroupsPolicy'] = True
        self.disabled_network_policy = True
        with self.assertRaisesRegex(SystemExit, 'NetworkPolicy is disabled'):
            self.prepare()

    def test_network_retries_reuse_podvm_group_and_only_allow_worker_guest_traffic(self):
        self.prepare()
        with patch.object(sys, 'argv', ['prepare-network.py']):
            network.main()
            network.main()
        self.assertEqual(sum(op == 'CreateSecurityGroup' for op, _ in self.calls), 1)
        rules = [a for op, a in self.calls if op == 'AuthorizeSecurityGroup']
        self.assertEqual({(a['SecurityGroupId'], a['SourceGroupId']) for a in rules},
                         {('sg-workers', 'sg-podvm'), ('sg-podvm', 'sg-workers')})
        self.assertFalse(any(a.get('SourceCidrIp') for a in rules))

    def test_import_image_and_reference_binding_survive_retry(self):
        self.selection.update(podvm_mode='import', guest='guest.qcow2', podvm_image_id='')
        cloud.write(self.handoff / 'outputs/guest.qcow2', 'qcow fixture')
        self.inputs()
        cloud.Cloud().save(oss_bucket='private-test', image_import_role_arn='arn-import')
        with patch.object(sys, 'argv', ['prepare-image.py']), patch.object(cloud.Cloud, 'oss', return_value='') as upload:
            image.main()
            image.main()
        upload.assert_called_once()
        self.assertEqual(upload.call_args.args[0], 'cp')
        self.assertEqual(upload.call_args.args[-2:], ('--acl', 'private'))
        imports = [a for op, a in self.calls if op == 'ImportImage']
        self.assertEqual(len(imports), 1)
        self.assertEqual((imports[0]['BootMode'], imports[0]['Features.NvmeSupport']), ('UEFI', 'supported'))
        binding = cloud.read(self.operator / 'podvm-image.json')
        self.assertEqual(binding['image_id'], 'm-imported')
        self.assertEqual(binding['references_sha256'], cloud.sha256(self.handoff / 'outputs/refs.json'))

    def test_existing_image_rejects_bad_metadata_and_tampered_handoff(self):
        with patch.object(sys, 'argv', ['prepare-image.py']):
            self.ecs_image['Features']['NvmeSupport'] = 'unsupported'
            with self.assertRaisesRegex(SystemExit, 'NVMe'):
                image.main()
            cloud.write(self.handoff / 'outputs/refs.json', 'tampered')
            with self.assertRaises(subprocess.CalledProcessError):
                image.main()
        self.assertFalse((self.operator / 'podvm-image-id.txt').exists())
        self.assertNotIn('ImportImage', [op for op, _ in self.calls])

    def test_roles_reuse_exact_scoped_policies_and_reject_extra_permissions(self):
        self.prepare()
        current = cloud.Cloud()
        current.save(podvm_vswitch_id='vsw-podvm')
        with patch.object(sys, 'argv', ['configure-identities.py']):
            identity.main()
            identity.main()
            self.assertEqual(sum(op == 'CreateRole' for op, _ in self.calls), 2)
            self.assertEqual(sum(op == 'AttachPolicyToRole' for op, _ in self.calls), 2)
            caa = cloud.read(self.operator / 'caa-trust.json')
            conditions = caa['Statement'][0]['Condition']['StringEquals']
            self.assertEqual(conditions['oidc:iss'], 'https://issuer.example')
            self.assertEqual(len(conditions['oidc:sub']), 2)
            permissions = cloud.read(self.operator / 'caa-permissions.json')
            self.assertIn('vswitch/vsw-podvm', json.dumps(permissions))
            self.attachments['cos-dev-csi'].append({'PolicyName': 'AdministratorAccess', 'PolicyType': 'System'})
            with self.assertRaisesRegex(SystemExit, 'Unexpected extra policies'):
                identity.main()

    def test_values_use_cloud_state_digests_and_the_same_ownership_tags(self):
        self.prepare()
        current = cloud.Cloud()
        current.save(podvm_vswitch_id='vsw-podvm', podvm_security_group_id='sg-podvm', podvm_image_id='m-test',
                     ram_roles={'caa': 'arn-caa', 'csi': 'arn-csi'})
        for name in ('cloud-api-adaptor', 'pause', 'peerpod-ctrl', 'peerpod_webhook', 'kata-deploy',
                     'kata_kubectl', 'caa-csi-block-driver', 'csi_provisioner', 'csi_node_registrar'):
            cloud.write(self.operator / (name + '-image.txt'), f'192.168.16.223:5000/{name}@sha256:' + 'a' * 64)
        initdata = self.operator / 'initdata'
        cloud.write(initdata, 'measured base initdata')
        with patch.object(sys, 'argv', ['configure-values.py']), patch.object(values, 'INITDATA', initdata):
            values.main()
            with self.assertRaisesRegex(SystemExit, 'Values already exist'):
                values.main()
        peer = yaml.safe_load((self.operator / 'peerpods-values.yaml').read_text())
        csi = yaml.safe_load((self.operator / 'csi-values.yaml').read_text())
        provider = peer['providerConfigs']['alibabacloud']
        self.assertEqual(provider['ALIBABA_CLOUD_ROLE_ARN'], 'arn-caa')
        self.assertEqual(provider['TAGS'], 'ClusterId=c-test,caa-csi-driver=caa-csi-block-driver')
        self.assertEqual(gzip.decompress(base64.b64decode(provider['INITDATA'])), initdata.read_bytes())
        self.assertEqual(csi['alibabacloud']['rrsa']['roleArn'], 'arn-csi')
        self.assertIn('@sha256:', peer['image']['tag'])
        self.assertNotIn('YOUR_', (self.operator / 'peerpods-values.yaml').read_text())

    def test_changed_inputs_cannot_redirect_existing_cloud_state(self):
        self.prepare()
        self.config['name'] = 'other-deployment'
        self.inputs()
        with self.assertRaisesRegex(SystemExit, 'changed after setup'):
            cloud.Cloud()
        self.config['name'] = 'cos-dev'
        self.selection['podvm_image_id'] = 'm-another-image'
        self.inputs()
        with self.assertRaisesRegex(SystemExit, 'handoff changed after setup'):
            cloud.Cloud()


class InputDiscovery(unittest.TestCase):
    def client(self):
        from unittest.mock import Mock
        client = Mock(region='cn-beijing', selection={'podvm_mode': 'import'})
        client.api.side_effect = self.api
        return client

    def api(self, product, operation, **args):
        if operation == 'DescribeClusterDetail':
            return {'region_id': 'cn-beijing', 'vpc_id': 'vpc-test', 'vswitch_ids': ['vsw-ack']}
        if operation == 'DescribeVSwitchAttributes':
            return {'VpcId': 'vpc-test', 'ZoneId': 'cn-beijing-i'}
        if operation == 'DescribeVpcAttribute':
            return {'CidrBlock': '192.168.0.0/16'}
        if operation == 'DescribeVSwitches':
            # Force pagination: allocations on both pages must be excluded.
            return {'TotalCount': 2, 'VSwitches': {'VSwitch': [
                {'CidrBlock': '192.168.0.0/24' if args['PageNumber'] == 1 else '192.168.1.0/24'}]}}
        if operation == 'GetCallerIdentity':
            return {'AccountId': '123'}
        self.fail(f'Discovery must not create resources: {operation}')

    def arguments(self, **overrides):
        from argparse import Namespace
        return Namespace(**{'name': 'cos-inputs-test', 'cluster_id': '', 'worker_vswitch_id': '',
                            'pod_vswitch_id': '', 'podvm_vswitch_id': '', 'oss_bucket': '',
                            'ack_api_access': 'public', 'oss_endpoint_network': 'public', **overrides})

    def test_new_cluster_uses_selected_cloud_network_and_avoids_allocations_on_all_pages(self):
        config, location = inputs.discover(self.client(), self.arguments(worker_vswitch_id='vsw-cloud'))
        self.assertEqual(config['worker_vswitch_id'], 'vsw-cloud')
        self.assertEqual(config['pod_vswitch_cidr'], '192.168.2.0/24')
        self.assertEqual(config['podvm_vswitch_cidr'], '192.168.3.0/24')
        self.assertTrue(config['oss_bucket'].startswith('cos-123-'))
        self.assertEqual(location['vpc_id'], 'vpc-test')

    def test_existing_cluster_reuses_ack_network_and_selected_bucket(self):
        config, _ = inputs.discover(self.client(), self.arguments(cluster_id='c-test', oss_bucket='existing-bucket'))
        self.assertEqual(config['worker_vswitch_id'], 'vsw-ack')
        self.assertEqual(config['pod_vswitch_cidr'], '')
        self.assertEqual(config['podvm_vswitch_cidr'], '192.168.2.0/24')
        self.assertEqual(config['oss_bucket'], 'existing-bucket')
        self.assertEqual(config['ack_api_access'], 'public')

    def test_cluster_configuration_is_independent_of_the_service_host_address(self):
        for target in ({'cluster_id': 'c-test'}, {'worker_vswitch_id': 'vsw-cloud'}):
            with self.subTest(target=target):
                client = self.client()
                args = self.arguments(oss_bucket='existing-bucket', **target)
                with patch.dict('os.environ', HOST_IP='203.0.113.10'):
                    public, public_location = inputs.discover(client, args)
                with patch.dict('os.environ', HOST_IP='192.168.16.223'):
                    private, private_location = inputs.discover(client, args)
                self.assertEqual(public, private)
                self.assertEqual(public_location, private_location)

    def test_new_cluster_requires_a_cloud_network_selection(self):
        with self.assertRaisesRegex(SystemExit, '--worker-vswitch-id'):
            inputs.discover(self.client(), self.arguments())

    def test_full_vpc_does_not_generate_overlapping_cidrs(self):
        with self.assertRaisesRegex(SystemExit, 'Not enough free'):
            inputs.free_cidrs('192.168.0.0/24', [{'CidrBlock': '192.168.0.0/24'}], 1)


class ImportStorage(CloudFixture, unittest.TestCase):
    def prepare_fixture(self):
        self.selection.update(podvm_mode='import', guest='guest.qcow2', podvm_image_id='')
        self.inputs()
        self.bucket = None

    def oss(self, operation, *args, **kwargs):
        if operation == 'mb':
            self.assertEqual(args[-2:], ('--acl', 'private'))
            self.bucket = 'Location : oss-cn-beijing\nACL : private\nOwner : 123\n'
            return ''
        self.assertEqual(operation, 'stat')
        return self.bucket

    def test_storage_creates_missing_bucket_and_official_authorization_then_reuses(self):
        self.prepare_fixture()
        with patch.object(sys, 'argv', ['prepare-storage.py']), patch.object(cloud.Cloud, 'oss', self.oss):
            with self.assertRaisesRegex(SystemExit, '--authorize-image-import'):
                storage.main()
        with patch.object(sys, 'argv', ['prepare-storage.py', '--authorize-image-import']), patch.object(cloud.Cloud, 'oss', self.oss):
            storage.main()
            storage.main()
        self.assertEqual(sum(op == 'CreateRole' for op, _ in self.calls), 1)
        self.assertEqual(sum(op == 'AttachPolicyToRole' for op, _ in self.calls), 1)
        self.assertEqual(self.attachments[storage.ROLE][0]['PolicyName'], storage.POLICY)
        self.assertEqual(self.state()['oss_bucket'], 'private-test')

    def test_storage_check_and_invalid_existing_bucket_do_not_create_or_change_it(self):
        self.prepare_fixture()
        self.roles[storage.ROLE] = {'Role': {'Arn': 'arn-import', 'AssumeRolePolicyDocument': storage.TRUST}}
        self.attachments[storage.ROLE] = [{'PolicyName': storage.POLICY, 'PolicyType': 'System'}]
        with patch.object(cloud.Cloud, 'oss', self.oss), patch.object(sys, 'argv', ['prepare-storage.py', '--check']):
            with self.assertRaisesRegex(SystemExit, 'does not exist'):
                storage.main()
        self.assertIsNone(self.bucket)
        self.assertFalse((self.operator / 'ack-state.json').exists())
        for info, error in [
            ('Location : oss-cn-shanghai\nACL : private\nOwner : 123\n', 'same region'),
            ('Location : oss-cn-beijing\nACL : public-read\nOwner : 123\n', 'must be private'),
            ('Location : oss-cn-beijing\nACL : private\nOwner : 456\n', 'another account'),
        ]:
            self.bucket = info
            with self.subTest(error=error), patch.object(cloud.Cloud, 'oss', self.oss), patch.object(sys, 'argv', ['prepare-storage.py']):
                with self.assertRaisesRegex(SystemExit, error):
                    storage.main()
            self.assertEqual(self.bucket, info)
        self.assertEqual(self.calls[-1][0], 'ListPoliciesForRole')
