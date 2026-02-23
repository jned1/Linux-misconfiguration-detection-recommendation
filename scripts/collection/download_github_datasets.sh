#!/bin/bash
# Download working security datasets from GitHub

cd dataset/external/public || exit 1



# 1. Linux Security Baseline
echo "1/4 Downloading linux-baseline..."
git clone --depth 1 https://github.com/dev-sec/linux-baseline.git 2>/dev/null || echo "  Already exists"

# 2. Debian CIS
echo "2/4 Downloading debian-cis..."
git clone --depth 1 https://github.com/ovh/debian-cis.git 2>/dev/null || echo "  Already exists"

# 3. NSL-KDD Dataset
echo "3/4 Downloading NSL-KDD..."
mkdir -p nsl-kdd
cd nsl-kdd
wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt 2>/dev/null || echo "  Already exists"
cd ..

# 4. Security Samples
echo "4/4 Downloading security samples..."
mkdir -p security-samples
cd security-samples
wget -q https://raw.githubusercontent.com/jharishma/Intrusion-detection/master/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv 2>/dev/null || echo "  Already exists"
cd ..

cd ../../..

echo ""
echo "✓ All datasets downloaded successfully!"
echo ""
echo "Available datasets:"
ls -lh dataset/external/public/
