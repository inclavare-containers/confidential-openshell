#!/usr/bin/env python3
"""Create/check private image-import storage and the standard ECS import role."""
import argparse
import json
from urllib.parse import unquote

from cloud import Cloud, require

ROLE = 'AliyunECSImageImportDefaultRole'
POLICY = 'AliyunECSImageImportRolePolicy'
TRUST = {'Version': '1', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                                     'Principal': {'Service': ['ecs.aliyuncs.com']}}]}


def bucket_info(cloud, bucket):
    output = cloud.oss('stat', 'oss://' + bucket, absent='NoSuchBucket')
    if output is None:
        return None
    # The pinned CLI's stat command has only text success output.
    result = {k.strip(): v.strip() for line in output.splitlines() if ':' in line for k, v in [line.split(':', 1)]}
    require(all(k in result for k in ('Location', 'ACL', 'Owner')), 'Cannot read bucket location, ACL and owner from OSS stat.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Read-only check; do not create storage or authorize ECS.')
    parser.add_argument('--authorize-image-import', action='store_true', help='Create the standard ECS import role and attach its official system policy if needed.')
    args = parser.parse_args()
    cloud = Cloud()
    if cloud.selection['podvm_mode'] != 'import':
        print('An approved ImageID was selected; OSS and image-import authorization are not needed.')
        return
    account = cloud.api('sts', 'GetCallerIdentity')['AccountId']
    role = cloud.api('ram', 'GetRole', RoleName=ROLE, absent='EntityNotExist.Role')
    require(role or (args.authorize_image_import and not args.check),
            f'{ROLE} is missing. Repeat with --authorize-image-import, or authorize ECS > Images > Import Image > Authorize in the console.')
    if not role:
        role = cloud.api('ram', 'CreateRole', RoleName=ROLE, AssumeRolePolicyDocument=json.dumps(TRUST),
                         Description='Standard ECS image import role')
    trust = role['Role']['AssumeRolePolicyDocument']
    trust = json.loads(unquote(trust)) if isinstance(trust, str) else trust
    require(trust == TRUST, f'{ROLE} has a different trust policy. Review it in RAM; this script does not replace existing trust.')
    policies = cloud.api('ram', 'ListPoliciesForRole', RoleName=ROLE)['Policies']['Policy']
    attached = any(p['PolicyName'] == POLICY and p['PolicyType'] == 'System' for p in policies)
    require(attached or (args.authorize_image_import and not args.check),
            f'{POLICY} is missing. Repeat with --authorize-image-import to attach the official system policy.')
    if not attached:
        cloud.api('ram', 'AttachPolicyToRole', RoleName=ROLE, PolicyName=POLICY, PolicyType='System')
    bucket = cloud.config['oss_bucket']
    info = bucket_info(cloud, bucket)
    if info is None:
        require(not args.check, f'OSS bucket {bucket} does not exist. Run this step without --check to create it.')
        cloud.oss('mb', 'oss://' + bucket, '--acl', 'private')
        info = bucket_info(cloud, bucket)
    require(info['Owner'] == account, 'OSS bucket belongs to another account; select a bucket owned by this operator account.')
    require(info['Location'] == 'oss-' + cloud.region, 'OSS bucket and the selected PodVM image must use the same region.')
    require(info['ACL'] == 'private', 'OSS bucket must be private; this script does not change an existing bucket ACL.')
    if not args.check:
        cloud.save(oss_bucket=bucket, image_import_role_arn=role['Role']['Arn'])
    print(f'Private image-import storage ready: oss://{bucket}, {info["Location"]}; role: {ROLE}.')


if __name__ == '__main__':
    main()
