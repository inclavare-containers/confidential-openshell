#!/usr/bin/env python3
"""Select a publisher's existing image, reference map and authenticated reference checksum."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(prog='./cos build guest-existing', description=__doc__)
    parser.add_argument('--region', default='cn-beijing')
    parser.add_argument('--image-id')
    parser.add_argument('--references', type=Path)
    parser.add_argument('--reference-sha256')
    args = parser.parse_args()
    subprocess.run(['bash', str(Path(__file__).with_name('check-region.sh')), args.region], check=True)
    image = args.image_id or input('Publisher ECS ImageID in the selected region: ').strip()
    references = str(args.references or input('Path to the matching reference JSON from the publisher: ').strip())
    checksum = args.reference_sha256 or input('Reference SHA-256 obtained from the publisher: ').strip()
    subprocess.run(['bash', str(Path(__file__).with_name('select-guest.sh')), 'existing',
                    args.region, image, references, checksum], check=True)


if __name__ == '__main__':
    main()
