#!/bin/bash

# Usage: ./scan.sh <image-name>
IMAGE=$1

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <image-name>"
  exit 1
fi

# Check if Trivy is installed
if ! command -v trivy &> /dev/null; then
  echo "Trivy not found. Installing..."
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
fi

# Scan the image and save the output
trivy image --format json -o report.json "$IMAGE"
echo "Scan complete. Report saved to report.json"
