#! /usr/bin/env bash

pushd $(dirname $0)
. ./imagename

CONTAINERS_REGISTRIES_CONF="$(pwd)/registries.conf"

# see https://stackoverflow.com/a/2924755 for switching boldface on/off
bold=$(tput bold)
normal=$(tput sgr0)

echo "${bold}**** Creating ${IMAGE} build-env image ****${normal}"
podman build -f Dockerfile.dcaf -t $USER/$IMAGE:build-env ..

popd
