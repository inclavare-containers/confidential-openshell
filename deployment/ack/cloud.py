"""Small shared helpers for the separate ACK deployment steps. No SDK required."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OPERATOR = Path(os.environ.get('OPERATOR_DIR', '/var/lib/openshell-confidential/operator/cluster-config'))
HANDOFF = Path(os.environ.get('HANDOFF', '/var/lib/openshell-confidential/operator/handoff'))


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


class Client:
    def __init__(self):
        require((HANDOFF / 'selection.json').is_file(), 'Unpack the verified release handoff first (deployment step 2).')
        self.selection = read(HANDOFF / 'selection.json')
        self.region = self.selection['podvm_region']

    def api(self, product, operation, *, body=None, absent=None, **parameters):
        args = ['aliyun', product, operation, '--region', self.region]
        profile = os.environ.get('ALIBABA_CLOUD_PROFILE')
        if profile:
            args += ['--profile', profile]
        for key, value in parameters.items():
            if value is not None:
                value = str(value).lower() if isinstance(value, bool) else str(value)
                args.append(f'--{key}={value}')
        if body is not None:
            args += ['--body', json.dumps(body, separators=(',', ':'))]
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode:
            if absent and absent in result.stderr:
                return None
            raise SystemExit(f'{product} {operation} failed:\n{result.stderr}')
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def oss(self, operation, *arguments, absent=None):
        suffix = '-internal' if self.config['oss_endpoint_network'] == 'internal' else ''
        args = ['aliyun', 'oss', operation, *map(str, arguments), '-e',
                f'https://oss-{self.region}{suffix}.aliyuncs.com']
        if os.environ.get('ALIBABA_CLOUD_PROFILE'):
            args += ['--profile', os.environ['ALIBABA_CLOUD_PROFILE']]
        result = subprocess.run(args, capture_output=True, text=True, timeout=900)
        if result.returncode:
            if absent and absent in result.stderr:
                return None
            raise SystemExit(f'OSS {operation} failed:\n{result.stderr}')
        return result.stdout


class Cloud(Client):
    def __init__(self):
        os.umask(0o077)
        super().__init__()
        require((OPERATOR / 'ack.json').is_file(), 'Run python3 deployment/ack/configure-inputs.py first.')
        self.config = read(OPERATOR / 'ack.json')
        self.name = self.config['name']
        require(re.fullmatch(r'[a-z][a-z0-9-]{1,39}', self.name), 'Use a name of 2–40 lowercase letters, digits or hyphens.')
        require(self.config['ack_api_access'] in ('public', 'private'), 'ack_api_access must be public or private.')
        require(self.config['oss_endpoint_network'] in ('public', 'internal'), 'oss_endpoint_network must be public or internal.')
        if self.selection['podvm_mode'] == 'import':
            require(self.config['oss_bucket'] and not self.config['oss_bucket'].startswith('YOUR_'),
                    'Fill in oss_bucket in ack.json before starting setup.')
        digest = hashlib.sha256(json.dumps(self.config, sort_keys=True).encode()).hexdigest()
        self.path = OPERATOR / 'ack-state.json'
        handoff_digest = sha256(HANDOFF / 'SHA256SUMS')
        self.state = read(self.path) if self.path.exists() else {
            'name': self.name, 'region': self.region, 'config_sha256': digest, 'handoff_sha256': handoff_digest,
        }
        require(self.state['config_sha256'] == digest and self.state['region'] == self.region,
                'ack.json/region changed after setup began. Use a separate OPERATOR_DIR for another deployment.')
        require(self.state['handoff_sha256'] == handoff_digest,
                'Release handoff changed after setup began. Use a separate OPERATOR_DIR for another deployment.')

    def save(self, **updates):
        self.state.update(updates)
        write(self.path, self.state)

    def wait(self, description, get, ready, timeout=2400):
        deadline = time.monotonic() + timeout
        while True:
            value = get()
            if ready(value):
                return value
            require(time.monotonic() < deadline, f'Timed out waiting for {description}; repeat this step to resume.')
            print(f'Waiting for {description}…', flush=True)
            time.sleep(15)

    def cluster(self):
        require(self.state.get('cluster_id'), 'Run prepare-cluster.py first.')
        return self.api('cs', 'DescribeClusterDetail', ClusterId=self.state['cluster_id'])

    def switch(self, kind, vpc, zone):
        key = kind + '_vswitch_id'
        switch = self.state.get(key) or self.config.get(key)
        if not switch:
            response = self.api('vpc', 'CreateVSwitch', RegionId=self.region, VpcId=vpc, ZoneId=zone,
                                CidrBlock=self.config[kind + '_vswitch_cidr'],
                                VSwitchName=self.name + '-' + kind, ClientToken=self.name + '-' + kind,
                                **{'Tag.1.Key': 'confidential-openshell-owner', 'Tag.1.Value': self.name})
            switch = response['VSwitchId']
            self.save(**{key: switch})
        detail = self.wait('vSwitch ' + switch,
                           lambda: self.api('vpc', 'DescribeVSwitchAttributes', RegionId=self.region, VSwitchId=switch),
                           lambda d: d['Status'] == 'Available')
        require(detail['VpcId'] == vpc and detail['ZoneId'] == zone,
                f'{key} must be in the selected VPC and zone.')
        self.save(**{key: switch})
        return switch
