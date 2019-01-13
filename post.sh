#!/bin/sh
# Get path for dpkg
set -e
if [ -f ~/.profile ]; then
    . ~/.profile
fi

RESOURCES_VERSION="$(dpkg --info ${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/resources.deb | grep Version: | awk '{print $2}')"
if [ -z "${RESOURCES_VERSION}" ]; then
    echo "dpkg not found or resources.deb missing"
    exit 1
else
    echo "Bundled resources: ${RESOURCES_VERSION}"
fi
defaults write "${TARGET_BUILD_DIR}/${INFOPLIST_PATH}" BundledResources "${RESOURCES_VERSION}"
