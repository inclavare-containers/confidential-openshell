#!/usr/bin/env python3
"""Select and label Ready ACK workers without requiring node-name placeholders."""
import argparse

from workers import nodes
from cloud import Cloud, require, run


def eligible(node):
    labels = node['metadata'].get('labels', {})
    return (not any(key in labels for key in ('node-role.kubernetes.io/control-plane', 'node-role.kubernetes.io/master')) and
            any(c['type'] == 'Ready' and c['status'] == 'True' for c in node['status'].get('conditions', [])))


def choose(current, created, requested, saved, prompt=input):
    candidates = [n['metadata']['name'] for n in current if eligible(n)]
    require(candidates, 'No Ready workers are available.')
    if requested:
        result = requested
    elif created or len(candidates) == 1:
        result = candidates
    elif saved:
        result = saved
    else:
        for index, name in enumerate(candidates, 1):
            print(f'  {index}. {name}', flush=True)
        answer = prompt('Worker numbers to configure (space-separated): ').split()
        require(answer and all(x.isdigit() and 1 <= int(x) <= len(candidates) for x in answer),
                'Enter numbers from the worker list, or pass --nodes followed by their names.')
        result = [candidates[int(x) - 1] for x in answer]
    require(result and len(set(result)) == len(result) and all(x in candidates for x in result),
            'Selected nodes must be distinct Ready workers. Repeat with --nodes to select current workers.')
    return result


def main():
    parser = argparse.ArgumentParser(prog='./cos workers select', description=__doc__)
    parser.add_argument('--nodes', nargs='+', help='Optional explicit worker names; default: discover, or select interactively for a shared cluster.')
    args = parser.parse_args()
    cloud = Cloud()
    current = nodes()
    selected = choose(current, cloud.state.get('created_cluster'), args.nodes, cloud.state.get('worker_nodes'))
    previous = (set(cloud.state.get('worker_nodes', [])) - set(selected)) & {n['metadata']['name'] for n in current}
    if previous:
        run(['kubectl', 'label', 'node', *sorted(previous), 'confidential.openshell.ai/worker-', '--overwrite'])
    run(['kubectl', 'label', 'node', *selected, 'confidential.openshell.ai/worker=', '--overwrite'])
    cloud.save(worker_nodes=selected)
    print('Deployment workers selected: ' + ', '.join(selected), flush=True)
    print('Registry and Kata configuration steps will use these workers through ECS Cloud Assistant; no worker SSH alias is needed.', flush=True)


if __name__ == '__main__':
    main()
