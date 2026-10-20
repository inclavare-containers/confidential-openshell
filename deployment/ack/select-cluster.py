#!/usr/bin/env python3
"""Create a complete new ACK environment, or check and attach an existing cluster."""
import argparse
import subprocess
import sys

from cloud import Client, OPERATOR, ROOT, read, require


def main():
    require(len(sys.argv) > 1 and sys.argv[1] in ('create', 'attach'), 'Use ./cos cluster create or ./cos cluster attach.')
    mode = sys.argv[1]
    parser = argparse.ArgumentParser(prog='./cos cluster ' + mode, description=__doc__)
    if mode == 'create':
        parser.add_argument('--zone', help='Optional zone; default: available worker/TDX capacity.')
        parser.add_argument('--vpc-cidr', help='Optional dedicated VPC CIDR; default: 10.64.0.0/16.')
    else:
        parser.add_argument('--cluster-id', help='Existing ACK ID; omit to choose from a list.')
    parser.set_defaults(cluster_id=None, zone=None, vpc_cidr=None)
    parser.add_argument('--name', help='Deployment resource name; default: a generated unique name.')
    parser.add_argument('--private-api', action='store_true', help='Use routed private ACK API access instead of public API.')
    args = parser.parse_args(sys.argv[2:])
    path = OPERATOR / 'ack.json'
    if path.exists():
        config = read(path)
        require(bool(config['cluster_id']) == (mode == 'attach'),
                'This operator directory already describes the other cluster path. Keep its state; use another OPERATOR_DIR for another deployment.')
        for supplied, saved in ((args.cluster_id, config['cluster_id']), (args.name, config['name']),
                                (args.zone, config.get('zone_id')), (args.vpc_cidr, config.get('vpc_cidr'))):
            require(not supplied or supplied == saved, f'Inputs already saved in {path}; do not change them during a retry.')
        require(not args.private_api or config['ack_api_access'] == 'private',
                'The saved deployment uses public API access. Keep its inputs when retrying.')
        print(f'Resuming saved {mode} inputs: {config["name"]} ({path}).', flush=True)
    else:
        options = []
        if mode == 'create':
            options.append('--new')
            for flag, value in (('--zone', args.zone), ('--vpc-cidr', args.vpc_cidr)):
                if value:
                    options += [flag, value]
        else:
            cluster_id = args.cluster_id
            if not cluster_id:
                client = Client()
                page = 1
                while True:
                    result = client.api('cs', 'DescribeClustersV1', region_id=client.region, page_size=100, page_number=page)
                    for row in result['clusters']:
                        print(f'{row["cluster_id"]}  {row["name"]}  {row["state"]}', flush=True)
                    total = result.get('page_info', {}).get('total_count', len(result['clusters']))
                    if page * 100 >= int(total):
                        break
                    page += 1
                cluster_id = input('Existing ACK cluster ID from the list: ').strip()
                require(cluster_id, 'No cluster selected.')
            options += ['--cluster-id', cluster_id]
        if args.name:
            options += ['--name', args.name]
        if args.private_api:
            options += ['--ack-api-access', 'private']
        subprocess.run([sys.executable, str(ROOT / 'deployment/ack/configure-inputs.py'), *options], check=True)
    subprocess.run([sys.executable, str(ROOT / 'deployment/ack/prepare-cluster.py'),
                    *(['--create'] if mode == 'create' else [])], check=True)


if __name__ == '__main__':
    main()
