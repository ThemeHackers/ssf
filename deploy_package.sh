#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ -f "./.venv/bin/python3" ]; then
    PYTHON_CMD="./.venv/bin/python3"
    TWINE_CMD="./.venv/bin/twine"
    echo -e "${GREEN}[+] Using venv: $PYTHON_CMD${NC}"
else
    PYTHON_CMD="python3"
    TWINE_CMD="twine"
    echo -e "${GREEN}[+] Using system python: $PYTHON_CMD${NC}"
fi

export TWINE_USERNAME="__token__"
if [ -z "$TWINE_PASSWORD" ] && [ -n "$PYPI_TOKEN" ]; then
    export TWINE_PASSWORD="${PYPI_TOKEN}"
fi


echo -e "${GREEN}[+] Fetching latest changes from GitHub...${NC}"
git pull origin $(git rev-parse --abbrev-ref HEAD)
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Git pull failed. Please resolve conflicts or check connection.${NC}"
    exit 1
fi


echo "---------------------------------------------------"
echo -e "${CYAN}🚀 Starting Automated Deployment (Local Only)${NC}"
echo "---------------------------------------------------"

$PYTHON_CMD -c "import build" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] 'build' module not found. Installing...${NC}"
    $PYTHON_CMD -m pip install build twine
fi

CURRENT_VERSION=$("$PYTHON_CMD" -c "
import re
try:
    with open('pyproject.toml', 'r') as f:
        content = f.read()
        match = re.search(r'version = \"(\d+\.\d+\.\d+)\"', content)
        if match:
            print(match.group(1))
        else:
            print('')
except:
    print('')
")

if [ -z "$CURRENT_VERSION" ]; then
    echo -e "${RED}❌ Could not detect current version from pyproject.toml${NC}"
    exit 1
fi

echo -e "Current Version: ${YELLOW}$CURRENT_VERSION${NC}"

IFS='.' read -r -a PARTS <<< "$CURRENT_VERSION"
MAJOR="${PARTS[0]}"
MINOR="${PARTS[1]}"
PATCH="${PARTS[2]}"

NEXT_PATCH="$MAJOR.$MINOR.$((PATCH + 1))"
NEXT_MINOR="$MAJOR.$((MINOR + 1)).0"
NEXT_MAJOR="$((MAJOR + 1)).0.0"

echo ""
echo "Select update type:"
echo -e "1) ${GREEN}Patch${NC} : $CURRENT_VERSION -> $NEXT_PATCH"
echo -e "2) ${YELLOW}Minor${NC} : $CURRENT_VERSION -> $NEXT_MINOR"
echo -e "3) ${RED}Major${NC} : $CURRENT_VERSION -> $NEXT_MAJOR"
echo -e "4) Custom"

read -p "Enter choice [1-4]: " CHOICE

case $CHOICE in
    1) NEW_VERSION="$NEXT_PATCH" ;;
    2) NEW_VERSION="$NEXT_MINOR" ;;
    3) NEW_VERSION="$NEXT_MAJOR" ;;
    4)
        read -p "Enter new version (e.g., 1.2.3): " CUSTOM_VER
        if [[ ! "$CUSTOM_VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}❌ Invalid version format.${NC}"
            exit 1
        fi
        NEW_VERSION="$CUSTOM_VER"
        ;;
    *)
        echo -e "${RED}❌ Invalid choice.${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "🚀 Target Version: ${CYAN}$NEW_VERSION${NC}"

echo -e "${GREEN}[+] Updating version in source files...${NC}"

"$PYTHON_CMD" -c "
import re
new_ver = '$NEW_VERSION'
with open('pyproject.toml', 'r') as f:
    content = f.read()
content = re.sub(r'version = \"\d+\.\d+\.\d+\"', f'version = \"{new_ver}\"', content)
with open('pyproject.toml', 'w') as f:
    f.write(content)
"

sed -i "s/Supabase Audit Framework v[0-9]*\.[0-9]*\.[0-9]*/Supabase Audit Framework v$NEW_VERSION/g" ssf/__main__.py
sed -i "s/subtitle =\"v[0-9]*\.[0-9]*\.[0-9]*\"/subtitle =\"v$NEW_VERSION\"/g" ssf/core/banner.py
sed -i "s/__version__ = \"[0-9]*\.[0-9]*\.[0-9]*\"/__version__ = \"$NEW_VERSION\"/g" ssf/__init__.py
sed -i "s/# Supabase Security Framework (ssf) v[0-9]*\.[0-9]*\.[0-9]*/# Supabase Security Framework (ssf) v$NEW_VERSION/g" README.md

echo -e "${GREEN}[+] Files updated.${NC}"


echo -e "${GREEN}[+] Committing and Pushing to GitHub...${NC}"
git add pyproject.toml ssf/__main__.py ssf/core/banner.py ssf/__init__.py README.md
git commit -m "Release v$NEW_VERSION: Improved logic and new feature arrivals"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Created commit.${NC}"
    if git rev-parse "v$NEW_VERSION" >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] Tag v$NEW_VERSION already exists locally. Skipping tag creation.${NC}"
    else
        git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
        echo -e "${GREEN}[+] Created tag v$NEW_VERSION.${NC}"
    fi
    
    echo -e "${GREEN}[+] Pushing changes to origin...${NC}"
    git push origin HEAD
    git push origin "v$NEW_VERSION"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ GitHub Push Successful!${NC}"
    else
        echo -e "${RED}⚠️ GitHub Push Failed. Proceeding to build...${NC}"
    fi
else
    echo -e "${YELLOW}[!] Nothing to commit. Proceeding...${NC}"
fi


echo -e "${GREEN}[+] Cleaning old artifacts...${NC}"
rm -rf dist/* build/ *.egg-info

echo -e "${GREEN}[+] Building new package...${NC}"
"$PYTHON_CMD" -m build

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Build failed. Aborting.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Uploading to PyPI...${NC}"
PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring $TWINE_CMD upload dist/* --non-interactive

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ PyPI Upload Successful! Version $NEW_VERSION is live.${NC}"
else
    echo -e "${RED}❌ PyPI Upload Failed!${NC}"
    exit 1
fi
