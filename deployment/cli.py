#!/usr/bin/env python3
"""Public command entry point. Component scripts own their individual operations."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OPERATOR = Path(os.environ.get('OPERATOR_DIR', '/var/lib/openshell-confidential/operator/cluster-config'))
HANDOFF = Path(os.environ.get('HANDOFF', '/var/lib/openshell-confidential/operator/handoff'))

# One command per operator step. Keep implementation in the component directory.
STEPS = {
    'host packages': ('Install Ubuntu build packages and start Docker', 'deployment/build/install-host-packages.sh', ['build'], 'host toolchains'),
    'host service-packages': ('Install Ubuntu service packages and start Docker', 'deployment/build/install-host-packages.sh', ['service'], 'host tools'),
    'host toolchains': ('Install the pinned Rust and Go toolchains', 'deployment/build/install-toolchains.sh', [], 'host tools'),
    'host tools': ('Install the pinned release tools', 'deployment/build/install-release-tools.sh', [], 'build sources'),
    'host cloud-tools': ('Install the Alibaba Cloud CLI', 'deployment/ack/install-tools.sh', [], 'deploy configure'),
    'build sources': ('Fetch and check pinned sources and charts', 'deployment/build/fetch-inputs.sh', [], 'build driver'),
    'build driver': ('Build the confidential OpenShell driver', 'deployment/build/build-driver.sh', [], 'build kata-shim'),
    'build kata-shim': ('Build and test the Kata host shim', 'deployment/build/build-kata-shim.sh', [], 'build caa'),
    'build caa': ('Build the Alibaba Cloud API adaptor image', 'deployment/build/build-caa.sh', [], 'build csi'),
    'build csi': ('Build the encrypted workspace CSI image and chart', 'deployment/build/build-csi.sh', [], 'build controller'),
    'build controller': ('Build the Alibaba PeerPod controller image', 'deployment/build/build-controller.sh', [], 'build test-cache'),
    'build test-cache': ('Download dependencies for the offline tests', 'deployment/build/cache-test-dependencies.sh', [], 'build test'),
    'build test': ('Run the offline integration tests', 'tests/run.sh', [], 'build guest'),
    'build guest': ('Build, verify and select the Ubuntu guest image', 'deployment/build/build-guest.sh', [], 'build package'),
    'build guest-existing': ('Select an existing guest image and its published references', 'deployment/build/select-existing-guest.py', [], 'build package'),
    'build package': ('Package the public release and record its checksum', 'deployment/build/package-release.sh', [], 'release install'),
    'release install': ('Verify and install the release on the trusted service host', 'deployment/build/install-release.py', [], 'host cloud-tools'),
    'cluster create': ('Create a dedicated VPC, ACK Pro cluster and workers', 'deployment/ack/select-cluster.py', ['create'], 'cloud network'),
    'cluster attach': ('Check and connect an existing ACK cluster', 'deployment/ack/select-cluster.py', ['attach'], 'cloud network'),
    'cloud network': ('Create the PodVM network and security group', 'deployment/ack/prepare-network.py', [], 'cloud image'),
    'cloud image': ('Prepare private import storage and confirm/import the guest image', 'deployment/ack/install-image.sh', [], 'cloud identities'),
    'cloud identities': ('Create scoped CAA and CSI runtime identities', 'deployment/ack/configure-identities.py', [], 'workers select'),
    'workers select': ('Select the ACK workers for Kata and CAA', 'deployment/peerpods/select-workers.py', [], 'trustee certificates'),
    'trustee certificates': ('Create the Trustee CA, server certificate and AS signer', 'deployment/trustee/create-certificates.sh', [], 'trustee install'),
    'trustee install': ('Install the official Trustee containers and service units', 'deployment/trustee/install.sh', [], 'trustee start'),
    'trustee reports': ('Enable passive appraisal collection on the Trustee host', 'deployment/trustee/configure-reports.py', ['trustee'], 'gateway reports'),
    'gateway reports': ('Enable historical appraisal display in driver conditions', 'deployment/trustee/configure-reports.py', ['gateway'], None),
    'trustee connect': ('Connect to an existing dedicated Trustee using its admin identity', 'deployment/trustee/configure-client.py', [], 'deploy initdata'),
    'trustee start': ('Start Trustee, register references and check anonymous denial', 'deployment/trustee/start.sh', [], 'deploy initdata'),
    'deploy initdata': ('Generate the public base initdata', 'deployment/guest/install-initdata.sh', [], 'registry start'),
    'registry start': ('Start the private TLS image registry', 'deployment/peerpods/start-registry.sh', [], 'registry publish'),
    'registry publish': ('Publish all images and the Kata host shim', 'deployment/peerpods/publish-all.sh', [], 'workers registry'),
    'workers registry': ('Install worker registry trust and verify real CRI pulls', 'deployment/peerpods/configure-worker-registry.py', [], 'cluster dependencies'),
    'cluster dependencies': ('Install Agent Sandbox and cert-manager', 'deployment/peerpods/install-prerequisites.sh', [], 'cluster values'),
    'cluster values': ('Generate private PeerPods and CSI values', 'deployment/peerpods/configure-values.py', [], 'cluster peerpods'),
    'cluster peerpods': ('Install Kata and PeerPods and wait for rollouts', 'deployment/peerpods/install-peerpods.sh', [], 'workers configure'),
    'workers configure': ('Configure and verify the active worker Kata profiles', 'deployment/peerpods/configure-workers.py', [], 'cluster csi'),
    'cluster csi': ('Install CSI and verify the DaemonSet rollout', 'deployment/peerpods/install-csi.sh', [], 'gateway install'),
    'gateway install': ('Install native OpenShell, identity, RBAC and driver configuration', 'deployment/openshell/install.sh', [], 'gateway start'),
    'gateway start': ('Start and check the confidential driver and Gateway', 'deployment/openshell/start-services.sh', [], 'gateway login'),
    'gateway login': ('Register and check the native operator CLI identity', 'deployment/openshell/login.sh', [], None),
}


def configuration():
    path = OPERATOR / 'operator.json'
    return json.loads(path.read_text()) if path.exists() else {}


def configure(args):
    parser = argparse.ArgumentParser(prog='./cos deploy configure', description='Save the trusted service address; configure the normal Alibaba CLI identity.')
    parser.add_argument('--host-ip')
    parser.add_argument('--profile')
    for option in ('registry-addr', 'registry-ca', 'registry-cert', 'registry-key'):
        parser.add_argument('--' + option)
    options = parser.parse_args(args)
    started = time.monotonic()
    print('[deploy configure] START — Save the trusted service address and verify cloud access', flush=True)
    saved = configuration()
    address = options.host_ip or saved.get('host_ip') or input('Trusted service IPv4 reachable from ACK workers and guests: ').strip()
    ip = ipaddress.IPv4Address(address)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise SystemExit('Use the IPv4 address through which the cloud reaches this trusted host.')
    if saved.get('host_ip') and saved['host_ip'] != address and (OPERATOR / 'ack-state.json').exists():
        raise SystemExit('This deployment already uses another HOST_IP. Retain its address and certificates.')
    profile = options.profile or saved.get('profile', 'default')
    region = json.loads((HANDOFF / 'selection.json').read_text())['podvm_region']
    command = ['aliyun', 'sts', 'GetCallerIdentity', '--region', region, '--profile', profile]
    identity = subprocess.run(command, capture_output=True, text=True)
    if identity.returncode:
        print('Cloud identity check failed; configure the operator CLI profile below.', flush=True)
        print(identity.stderr.strip(), flush=True)
        # Credentials are entered on the terminal, never copied to the step log.
        subprocess.run(['aliyun', 'configure', '--profile', profile], check=True)
        identity = subprocess.run(command, capture_output=True, text=True)
    if identity.returncode:
        raise SystemExit('Cloud identity check failed:\n' + identity.stderr.strip())
    account = json.loads(identity.stdout)['AccountId']
    OPERATOR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = OPERATOR / 'operator.json'
    saved.update(host_ip=address, profile=profile)
    for key in ('registry_addr', 'registry_ca', 'registry_cert', 'registry_key'):
        if getattr(options, key) is not None:
            saved[key] = getattr(options, key)
    path.write_text(json.dumps(saved, indent=2) + '\n')
    path.chmod(0o600)
    print(f'Trusted service: {address}; cloud account: {account}; region: {region}', flush=True)
    print(f'Configuration saved: {path}. Future ./cos steps load it automatically.', flush=True)
    print(f'[deploy configure] OK ({round(time.monotonic() - started, 1)}s)', flush=True)
    print('Next: ./cos cluster create (new cluster), or ./cos cluster attach (existing cluster).', flush=True)


def environment():
    env = dict(os.environ)
    saved = configuration()
    if saved.get('host_ip'):
        env['HOST_IP'] = saved['host_ip']
    if saved.get('profile'):
        env['ALIBABA_CLOUD_PROFILE'] = saved['profile']
    for key, name in [('registry_addr', 'REGISTRY_ADDR'), ('registry_ca', 'REGISTRY_CA'),
                      ('registry_cert', 'REGISTRY_TLS_CERT'), ('registry_key', 'REGISTRY_TLS_KEY')]:
        if saved.get(key):
            env[name] = saved[key]
    env['OPERATOR_DIR'] = str(OPERATOR)
    env.setdefault('HANDOFF', str(HANDOFF))
    env['KUBECONFIG'] = str(OPERATOR / 'administrator-kubeconfig')
    return env


def status():
    saved = configuration()
    print(f'Operator directory: {OPERATOR}')
    print(f'Trusted service: {saved.get("host_ip", "not configured")}')
    path = OPERATOR / 'ack-state.json'
    if path.exists():
        state = json.loads(path.read_text())
        for key in ('region', 'cluster_id', 'vpc_id', 'zone_id', 'worker_vswitch_id',
                    'podvm_vswitch_id', 'podvm_security_group_id', 'podvm_image_id', 'worker_nodes'):
            if state.get(key):
                print(f'{key}: {state[key]}')
    for path in (ROOT / '.local/steps.json', OPERATOR / 'steps.json'):
        if path.exists():
            print('Last command results (recorded results, not a live health check):')
            for name, result in json.loads(path.read_text()).items():
                print(f'  {name}: {result["status"]} ({result["elapsed_seconds"]}s); {result["log"]}')


def run_step(name, args):
    title, script, fixed, following = STEPS[name]
    if set(args) & {'--help', '-h'}:
        if not script.endswith('.py'):
            options = ' [--region REGION]' if name == 'build guest' else ''
            print(f'Usage: ./cos {name}{options}\n{title}')
            return 0
        interpreter = sys.executable if script.endswith('.py') else 'bash'
        return subprocess.call([interpreter, str(ROOT / script), *(fixed if script.endswith('.py') else []), *args], cwd=ROOT, env=environment())
    if args and script.endswith('.sh') and name != 'build guest':
        raise SystemExit('This step takes no options. Run ./cos ' + name + ' --help for its usage.')
    env = environment()
    # Build logs remain private and are excluded from the public handoff.
    base = ROOT / '.local' if name.startswith(('host ', 'build ', 'release ')) else OPERATOR
    logs = base / 'logs'
    logs.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    log = logs / (stamp + '-' + name.replace(' ', '-') + '.log')
    print(f'[{name}] START — {title}\nLog: {log}', flush=True)
    started = time.monotonic()
    interpreter = sys.executable if script.endswith('.py') else 'bash'
    command = [interpreter, str(ROOT / script), *fixed, *args]
    env['PYTHONUNBUFFERED'] = '1'
    with log.open('wb') as output:
        log.chmod(0o600)
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for chunk in iter(lambda: os.read(process.stdout.fileno(), 4096), b''):
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            output.write(chunk)
            output.flush()
        code = process.wait()
        process.stdout.close()
    elapsed = round(time.monotonic() - started, 1)
    result = {'status': 'OK' if code == 0 else 'FAILED', 'elapsed_seconds': elapsed, 'log': str(log)}
    journal = base / 'steps.json'
    records = json.loads(journal.read_text()) if journal.exists() else {}
    records[name] = result
    temporary = journal.with_suffix('.tmp')
    temporary.write_text(json.dumps(records, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(journal)
    print(f'[{name}] {result["status"]} ({elapsed}s)', flush=True)
    if code:
        print(f'Stopped at this step. Read {log}, correct the reported error, then repeat:\n  ./cos {name} {shlex.join(args)}', flush=True)
    elif following:
        if name == 'host tools' and (not (ROOT / '.git').exists() or
                                     'host service-packages' in records):
            following = 'release install' if (ROOT / '.git').exists() else 'host cloud-tools'
        print(f'Next: ./cos {following}', flush=True)
    else:
        print('Step complete. See docs/attestation-records.md.' if name == 'gateway reports' else 'Gateway operator login checked. Continue with docs/first-agent.md.', flush=True)
    return code


def main():
    os.umask(0o077)
    args = sys.argv[1:]
    if args in ([], ['--help'], ['-h']):
        print('Usage: ./cos GROUP STEP [options]\n\nRun one step at a time. Each step prints START, OK/FAILED, its log and the next command.\n')
        print('  deploy configure        Save the trusted service address and configure cloud access')
        for name, (title, _, _, _) in STEPS.items():
            print(f'  {name:25s} {title}')
        print('  status                    Show saved resources and previous command results')
        return 0
    if args == ['status']:
        status()
        return 0
    groups = {name.split()[0] for name in STEPS} | {'deploy'}
    if args[0] in groups and (len(args) == 1 or args[1:] in (['--help'], ['-h'])):
        print(f'Usage: ./cos {args[0]} STEP [options]\n')
        if args[0] == 'deploy':
            print('  deploy configure          Save the trusted service address and cloud identity')
        for name, (title, _, _, _) in STEPS.items():
            if name.startswith(args[0] + ' '):
                print(f'  {name:25s} {title}')
        return 0
    if args[:2] == ['deploy', 'configure']:
        configure(args[2:])
        return 0
    name = ' '.join(args[:2])
    if name not in STEPS:
        raise SystemExit('Unknown step. Run ./cos --help for the available commands.')
    if name not in {'trustee reports', 'gateway reports'} and not name.startswith(('host ', 'build ', 'release ')) and not (set(args) & {'--help', '-h'}) and not configuration():
        raise SystemExit('Configure the trusted service address and cloud identity first: ./cos deploy configure.')
    return run_step(name, args[2:])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit('Interrupted. Check the step log before retrying.')
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from None
