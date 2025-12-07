#!/bin/bash


if [ -f .env ]; then
  echo "Loading .env file..."
  export $(grep -v '^#' .env | xargs)
fi


CURRENT_VERSION=$(grep -m 1 'version = ' pyproject.toml | awk -F '"' '{print $2}')
IFS='.' read -r -a VERSION_PARTS <<< "$CURRENT_VERSION"

NEW_PATCH=$((VERSION_PARTS[2] + 1))
NEW_VERSION="${VERSION_PARTS[0]}.${VERSION_PARTS[1]}.$NEW_PATCH"

echo "Current version: $CURRENT_VERSION"
echo "Bumping to version: $NEW_VERSION"

sed -i "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" pyproject.toml

echo "Cleaning dist directory..."
rm -rf dist/*


echo "Building package..."
python3 -m build


if [ $? -ne 0 ]; then
  echo "Build failed. Exiting."
  exit 1
fi

echo "Uploading to PyPI..."
twine upload dist/*
