#!/bin/bash

if [ -f "./.venv/bin/python3" ]; then
    PYTHON_CMD="./.venv/bin/python3"
    TWINE_CMD="./.venv/bin/twine"
    echo "[+] Using venv: $PYTHON_CMD"
else
    PYTHON_CMD="python3"
    TWINE_CMD="twine"
    echo "[+] Using system python: $PYTHON_CMD"
fi

export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="${PYPI_TOKEN}"  # Token removed. Set PYPI_TOKEN env var.

echo "---------------------------------------------------"
echo "🚀 Starting Automated Deployment"
echo "---------------------------------------------------"


get_version() {
    $PYTHON_CMD -c "
import re
with open('pyproject.toml', 'r') as f:
    content = f.read()
    match = re.search(r'version = \"(\d+\.\d+\.\d+)\"', content)
    if match:
        print(match.group(1))
"
}

NEW_VERSION=$(get_version)
echo "🚀 Deploying Version: $NEW_VERSION"

if [ -z "$NEW_VERSION" ]; then
    echo "❌ Could not detect version."
    exit 1
fi

echo "[+] Updating version in source files..."
sed -i "s/Supabase Audit Framework v[0-9]*\.[0-9]*\.[0-9]*/Supabase Audit Framework v$NEW_VERSION/g" ssf/__main__.py
sed -i "s/subtitle =\"v[0-9]*\.[0-9]*\.[0-9]*\"/subtitle =\"v$NEW_VERSION\"/g" ssf/core/banner.py
sed -i "s/__version__ = \"[0-9]*\.[0-9]*\.[0-9]*\"/__version__ = \"$NEW_VERSION\"/g" ssf/__init__.py
sed -i "s/# Supabase Security Framework (ssf) v[0-9]*\.[0-9]*\.[0-9]*/# Supabase Security Framework (ssf) v$NEW_VERSION/g" README.md


echo "[+] Cleaning old artifacts..."
rm -rf dist/* build/ *.egg-info



echo "[+] Building new package..."
$PYTHON_CMD -m build

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Aborting."
    exit 1
fi



echo "[+] Uploading to PyPI..."
PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring $TWINE_CMD upload dist/* --non-interactive

if [ $? -eq 0 ]; then
    echo "✅ PyPI Upload Successful!"
else
    echo "❌ PyPI Upload Failed!"
    exit 1
fi
