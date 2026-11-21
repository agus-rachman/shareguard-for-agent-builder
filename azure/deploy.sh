#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
#
# Builds the Function app package and deploys infrastructure + code.
#
#   ./azure/deploy.sh <resource-group> <parameters.json> [--code-only]
#
# Needs: Azure CLI (az) with Bicep, signed in with rights on the resource group.
# The deploying machine's public IP must be in deploymentIpRanges (or run this from
# inside the VNet), because the Function apps deny inbound traffic otherwise.
set -euo pipefail

RG="${1:?resource group}"
PARAMS="${2:?parameters file}"
MODE="${3:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build/functionapp"

rm -rf "$BUILD" && mkdir -p "$BUILD"
cp "$ROOT"/azure/functionapp/{function_app.py,host.json,requirements.txt,.funcignore} "$BUILD"/
cp -r "$ROOT/src/absg" "$BUILD/absg"
find "$BUILD" -name '__pycache__' -prune -exec rm -rf {} +
(cd "$BUILD" && zip -qr ../functionapp.zip .)
echo "Package: $ROOT/build/functionapp.zip"

if [[ "$MODE" != "--code-only" ]]; then
  az deployment group create -g "$RG" -f "$ROOT/azure/infra/main.bicep" -p "@$PARAMS" \
     --query properties.outputs -o json > "$ROOT/build/outputs.json"
  echo "Outputs: $ROOT/build/outputs.json"
fi

OUT="$ROOT/build/outputs.json"
GUARD=$(python3 -c "import json;print(json.load(open('$OUT'))['guardAppName']['value'])")
SIGNER=$(python3 -c "import json;print(json.load(open('$OUT'))['signerAppName']['value'])")
for APP in "$GUARD" "$SIGNER"; do
  echo "Deploying code to $APP"
  az functionapp deployment source config-zip -g "$RG" -n "$APP" --src "$ROOT/build/functionapp.zip" --build-remote true
done
echo "Done. Next: run the scripts in azure/scripts (see docs/azure-deployment.md)."
