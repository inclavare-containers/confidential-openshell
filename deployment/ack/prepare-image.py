#!/usr/bin/env python3
"""Verify the handoff, confirm/import its ECS image and record the reference binding."""
import argparse

from cloud import Cloud, HANDOFF, OPERATOR, require, run, sha256, write


def validate_image(image):
    require(image['Status'] == 'Available' and image['OSType'].lower() == 'linux' and
            image['Architecture'] == 'x86_64' and image['BootMode'] == 'UEFI' and
            image.get('Features', {}).get('NvmeSupport') == 'supported',
            'PodVM image must be Available, Linux/x86_64, UEFI and NVMe-capable.')


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    cloud = Cloud()
    # unpack-release.sh authenticates SHA256SUMS; verify its contents again before upload.
    run(['sha256sum', '-c', 'SHA256SUMS', '--quiet'], cwd=HANDOFF)
    selection = cloud.selection
    refs = HANDOFF / 'outputs' / selection['references']
    image_id = cloud.state.get('podvm_image_id')
    qcow_digest = None
    if selection['podvm_mode'] == 'import':
        qcow = HANDOFF / 'outputs' / selection['guest']
        qcow_digest = sha256(qcow)
        if not image_id:
            bucket = cloud.config['oss_bucket']
            require(bucket and not bucket.startswith('YOUR_'), 'Fill in oss_bucket in ack.json.')
            key = f'confidential-openshell/{cloud.name}/{qcow_digest}.qcow2'
            require(cloud.state.get('oss_bucket') == bucket and cloud.state.get('image_import_role_arn'),
                    'Run python3 deployment/ack/prepare-storage.py before importing the image.')
            cloud.oss('cp', str(qcow), f'oss://{bucket}/{key}', '--force', '--acl', 'private')
            # Match the official CLI example: flat RPC fields with local metadata checks disabled.
            response = cloud.api('ecs', 'ImportImage', force=True, method='POST', RegionId=cloud.region,
                                 ImageName=cloud.name + '-' + qcow_digest[:12], Description=cloud.name,
                                 ClientToken=cloud.name + '-' + qcow_digest[:20],
                                 OSType='linux', Platform='Ubuntu', Architecture='x86_64', BootMode='UEFI',
                                 **{'Features.NvmeSupport': 'supported', 'DiskDeviceMapping.1.OSSBucket': bucket,
                                    'DiskDeviceMapping.1.OSSObject': key, 'DiskDeviceMapping.1.Format': 'QCOW2',
                                    'DiskDeviceMapping.1.DiskImageSize': '20',
                                    'Tag.1.Key': 'confidential-openshell-owner', 'Tag.1.Value': cloud.name})
            image_id = response['ImageId']
            cloud.save(podvm_image_id=image_id, oss_object=f'oss://{bucket}/{key}')
    else:
        require(selection['podvm_mode'] == 'existing', 'Unknown PodVM selection mode.')
        image_id = selection['podvm_image_id']
    require(image_id, 'Missing ImageID in the selected handoff.')

    def get_image():
        rows = cloud.api('ecs', 'DescribeImages', RegionId=cloud.region, ImageId=image_id)['Images']['Image']
        require(len(rows) == 1, 'ImageID not found in the selected region.')
        require(rows[0]['Status'] not in ('ImportFailed', 'UnAvailable'), 'ECS image import failed; inspect its task in ECS.')
        return rows[0]

    image = cloud.wait('ECS image import', get_image, lambda d: d['Status'] == 'Available')
    validate_image(image)
    cloud.save(podvm_image_id=image_id)
    write(OPERATOR / 'podvm-image-id.txt', image_id + '\n')
    write(OPERATOR / 'podvm-image.json', {
        'region': cloud.region, 'image_id': image_id, 'references_sha256': sha256(refs),
        'qcow2_sha256': qcow_digest, 'handoff_sha256': sha256(HANDOFF / 'SHA256SUMS'),
    })
    print(f'PodVM image ready: {image_id}; image/reference binding: {OPERATOR / "podvm-image.json"}')


if __name__ == '__main__':
    main()
