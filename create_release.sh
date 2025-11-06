#!/bin/bash
# Script to create GitHub release with binaries
# Requires GITHUB_TOKEN environment variable

REPO="CSA-RH/aro-eip-toolkit"
VERSION="v0.1.0"
TAG="v0.1.0"

# Create release via GitHub API
echo "Creating release $VERSION..."
RELEASE_RESPONSE=$(curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  "https://api.github.com/repos/$REPO/releases" \
  -d "{
    \"tag_name\": \"$TAG\",
    \"name\": \"Release $VERSION\",
    \"body\": \"EIP Toolkit v0.1.0\\n\\nFeatures:\\n- EIP and CPIC monitoring with real-time status display\\n- Plotting for all logged metrics (per-node and cluster-level)\\n- Early exit behavior for quick status checks\\n- Cross-platform support (macOS ARM64, Linux x86_64)\\n- Mismatch detection and overcommitment tracking\\n- Comprehensive logging and visualization\\n\\nBinaries:\\n- eip-toolkit-darwin-arm64: macOS Apple Silicon\\n- eip-toolkit-linux-amd64: Linux x86_64\\n\",
    \"draft\": false,
    \"prerelease\": false
  }")

RELEASE_ID=$(echo "$RELEASE_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

if [ -z "$RELEASE_ID" ]; then
  echo "Error creating release. Response: $RELEASE_RESPONSE"
  exit 1
fi

echo "Release created with ID: $RELEASE_ID"

# Upload binaries
echo "Uploading eip-toolkit-darwin-arm64..."
curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@eip-toolkit-darwin-arm64" \
  "https://uploads.github.com/repos/$REPO/releases/$RELEASE_ID/assets?name=eip-toolkit-darwin-arm64" > /dev/null

echo "Uploading eip-toolkit-linux-amd64..."
curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@eip-toolkit-linux-amd64" \
  "https://uploads.github.com/repos/$REPO/releases/$RELEASE_ID/assets?name=eip-toolkit-linux-amd64" > /dev/null

echo "Release $VERSION created successfully!"
