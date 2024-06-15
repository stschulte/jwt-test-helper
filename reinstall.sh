#!/bin/bash
#
# Author: Stefan Schulte <stschulte@posteo.de>
#
# Small script to freshly start over installing all
# dependencies.
#
# Script can be used to upgrade all dependencies to
# to the latest version by simply having npm figure out
# the dependency tree again.
#
# Be careful as this will also upgrade over major versions

set -e

RUNTIME_DEPENDENCIES=(
  "tslib"
  "nock"
)

BUILDTIME_DEPENDENCIES=(
    "typescript"
    "@types/node"
    "eslint"
    "@eslint/js"
    "eslint-config-flat-gitignore"
    "eslint-plugin-perfectionist"
    "typescript-eslint"
    "vitest"
    "@vitest/coverage-v8"
)

if [[ ! -f package.json ]]; then
  echo "No package.json found. Are you executing the script in the right directory? Abort now" 1>&2
  exit 3
fi

echo "Cleanup"
rm -rf node_modules package-lock.json *.tgz coverage dist
sed -i \
  -e '/^  "dependencies"/,/^  \}/D' \
  -e '/^  "devDependencies"/,/^  \}/D' \
  -e 's/^\(  "homepage".*\),$/\1/' \
  package.json


echo ">> Installing dependencies"
for PKG in "${RUNTIME_DEPENDENCIES[@]}"; do
  echo " * ${PKG}"
done
npm install "${RUNTIME_DEPENDENCIES[@]}"

echo ">> Installing development dependencies"
for PKG in "${BUILDTIME_DEPENDENCIES[@]}"; do
  echo " * ${PKG}"
done
npm install --save-dev "${BUILDTIME_DEPENDENCIES[@]}"

echo ">> DONE"
