#!/usr/bin/env bash
usage='Usage: ./cos cloud image
Create/check private import storage, authorize the standard ECS import role and import or confirm the selected image.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
python3 deployment/ack/prepare-storage.py --authorize-image-import
python3 deployment/ack/prepare-image.py
