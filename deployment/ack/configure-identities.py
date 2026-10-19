#!/usr/bin/env python3
"""Render the maintained policies and create separate CAA/controller and CSI RAM roles."""
import argparse
import json
from urllib.parse import unquote

from cloud import Cloud, OPERATOR, ROOT, require, write


def document(value):
    return json.loads(unquote(value)) if isinstance(value, str) else value


def policies(cloud, account):
    values = {
        'ACCOUNT_ID': account, 'REGION': cloud.region, 'ACK_CLUSTER_ID': cloud.state['cluster_id'],
        'ACK_OIDC_PROVIDER_ARN': cloud.state['rrsa']['oidc_arn'],
        'ACK_OIDC_ISSUER': cloud.state['rrsa']['issuer'].split(',')[0],
        'VSWITCH_ID': cloud.state['podvm_vswitch_id'],
    }
    rendered = {}
    for component in ('caa', 'csi'):
        rendered[component] = {}
        for kind in ('trust', 'permissions'):
            text = (ROOT / f'deployment/ack/ram/{component}-{kind}.example.json').read_text()
            for key in sorted(values, key=len, reverse=True):
                text = text.replace(key, values[key])
            rendered[component][kind] = json.loads(text)
    return rendered


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    cloud = Cloud()
    require(cloud.state.get('podvm_vswitch_id'), 'Run prepare-network.py first.')
    identity = cloud.api('sts', 'GetCallerIdentity')
    account = identity['AccountId']
    require(f'::{account}:' in cloud.state['rrsa']['oidc_arn'], 'Caller and ACK OIDC provider belong to different accounts.')
    description = f'confidential-openshell:{cloud.name}:{cloud.state["cluster_id"]}'
    rendered = policies(cloud, account)
    roles = {}
    for component, documents in rendered.items():
        role_name = cloud.name + '-' + component
        policy_name = role_name + '-permissions'
        for kind, value in documents.items():
            write(OPERATOR / f'{component}-{kind}.json', value)
        role = cloud.api('ram', 'GetRole', RoleName=role_name, absent='EntityNotExist.Role')
        if role:
            require(role['Role'].get('Description') == description and
                    document(role['Role']['AssumeRolePolicyDocument']) == documents['trust'],
                    f'Existing role {role_name} has different ownership/trust. Use another deployment name.')
        else:
            role = cloud.api('ram', 'CreateRole', RoleName=role_name, Description=description,
                             AssumeRolePolicyDocument=json.dumps(documents['trust']))
        roles[component] = role['Role']['Arn']
        cloud.save(ram_roles=roles)
        policy = cloud.api('ram', 'GetPolicy', PolicyType='Custom', PolicyName=policy_name, absent='EntityNotExist.Policy')
        if policy:
            require(policy['Policy'].get('Description') == description,
                    f'Existing policy {policy_name} belongs to another deployment.')
            version = cloud.api('ram', 'GetPolicyVersion', PolicyType='Custom', PolicyName=policy_name,
                                VersionId=policy['Policy']['DefaultVersion'])
            require(document(version['PolicyVersion']['PolicyDocument']) == documents['permissions'],
                    f'Existing policy {policy_name} differs from the reviewed template.')
        else:
            cloud.api('ram', 'CreatePolicy', PolicyName=policy_name, Description=description,
                      PolicyDocument=json.dumps(documents['permissions']))
        attached = cloud.api('ram', 'ListPoliciesForRole', RoleName=role_name)['Policies']['Policy']
        require(all(p['PolicyName'] == policy_name and p['PolicyType'] == 'Custom' for p in attached),
                f'Unexpected extra policies on {role_name}; inspect RAM before continuing.')
        if not attached:
            cloud.api('ram', 'AttachPolicyToRole', PolicyType='Custom', PolicyName=policy_name, RoleName=role_name)
        print(f'{component}: {roles[component]}')
    print('RAM identities ready. Templates and ARNs are saved in OPERATOR_DIR.')


if __name__ == '__main__':
    main()
