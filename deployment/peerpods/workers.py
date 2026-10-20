"""Selected ACK workers and the official ECS Cloud Assistant execution path."""
import base64
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ack'))
from cloud import Cloud, OPERATOR, require, run


def nodes():
    env = {**os.environ, 'KUBECONFIG': str(OPERATOR / 'administrator-kubeconfig')}
    return json.loads(run(['kubectl', '--request-timeout=30s', 'get', 'nodes', '-o', 'json'],
                          env=env, capture_output=True).stdout)['items']


def selected(cloud):
    names = cloud.state.get('worker_nodes')
    require(names, 'Select the deployment workers first: ./cos workers select.')
    current = {n['metadata']['name']: n for n in nodes()}
    require(all(n in current for n in names), 'A selected worker is absent; repeat ./cos workers select with the current nodes.')
    result = []
    for name in names:
        provider = current[name]['spec'].get('providerID', '')
        match = re.search(r'(?:^|[./])(i-[a-z0-9]+)$', provider)
        require(match, f'Worker {name} has no ECS instance ID in providerID: {provider}')
        result.append((name, match[1]))
    return result


def execute(cloud, instance, command, description, timeout=180):
    print(f'{description}: {instance}…', flush=True)
    invocation = cloud.api('ecs', 'RunCommand', RegionId=cloud.region, Type='RunShellScript',
                           **{'InstanceId.1': instance}, ContentEncoding='Base64',
                           CommandContent=base64.b64encode(command.encode()).decode(),
                           KeepCommand=False, Timeout=timeout)['InvokeId']

    def result():
        response = cloud.api('ecs', 'DescribeInvocationResults', RegionId=cloud.region, InvokeId=invocation)
        rows = response.get('Invocation', {}).get('InvocationResults', {}).get('InvocationResult', [])
        return next((r for r in rows if r.get('InstanceId') == instance), None)

    row = cloud.wait(description + ' on ' + instance, result,
                     lambda r: r is not None and r.get('InvocationStatus') in
                     ('Success', 'Failed', 'Stopped', 'TimedOut', 'Error'), timeout=timeout + 60)
    output = base64.b64decode(row.get('Output', '')).decode(errors='replace')
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    require(row.get('InvocationStatus') == 'Success' and int(row.get('ExitCode', -1)) == 0,
            f'{description} failed on {instance}. Correct the error above and repeat this step.')
    return output


if __name__ == '__main__':
    import argparse
    import ipaddress
    parser = argparse.ArgumentParser(description='Check the Gateway network path from selected ACK workers.')
    parser.add_argument('--check-gateway', action='store_true', required=True)
    parser.parse_args()
    address = str(ipaddress.IPv4Address(os.environ['HOST_IP']))
    cloud = Cloud()
    command = 'python3 - <<\'PY\'\nimport socket\nwith socket.create_connection((' + repr(address) + ',9443),timeout=10):\n    print("Worker can reach Gateway TCP 9443")\nPY\n'
    for name, instance in selected(cloud):
        execute(cloud, instance, command, 'Gateway network reachability', timeout=30)
