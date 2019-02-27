#!/bin/sh
# Get path for dpkg
set -e
if [ -f ~/.profile ]; then
    . ~/.profile
fi

if [[ "${CODE_SIGNING_REQUIRED}" == "NO" ]]; then
  if which -s gtar; then
    TAR=gtar
  elif which -s gnutar; then
    TAR=gnutar
  else
    TAR=tar
  fi

  LISTSRC="${SOURCE_ROOT}/Undecimus/resources/lists.tar.lzma"
  pushd "${TEMP_DIR}"
  rm -rf lists
  mkdir lists
  pushd lists
  ${TAR} xf "${LISTSRC}"
  cp -a ../lists ../lists-packaged
  CURLARGS=("-H" "X-Firmware: 11.0" "-H" "X-Machine: iPhone0,0" "-H" "X-Unique-ID: 42" "-H" "User-Agent: Telesphoreo APT-HTTP/1.0.592")
  for file in $(ls); do
    echo ${file}
    tfile="${file}"
    if [[ "${file%_Packages}" != "${file}" ]]; then
      file="${file}.bz2"
    fi
    HTTPURL="http://${file//_//}"
    HTTPSURL="https://${file//_//}"
    if ! curl "${CURLARGS[@]}" -z ${tfile} -o "${file}" ${HTTPSURL} 2>/dev/null; then
      curl "${CURLARGS[@]}" -z ${tfile} -o ${file} ${HTTPURL} 2>/dev/null
    fi
    if [[ -f "${file}" && "${file%.bz2}" != "${file}" ]]; then
      if [ -f "${tfile}" ]; then
        rm "${tfile}"
      fi
      bunzip2 "${file}"
    fi
  done
  if diff -qr ../lists-packaged . > /dev/null; then
    echo Lists unchanged, continuing.
  else
    echo Lists updated, repacking.  This will take a while...
    if ! ${TAR} --use-compress-program="lzma -e9" --owner=root --group=wheel -cf "${LISTSRC}" *; then
      echo We need GNU tar please
      exit 1
    fi
    echo Done.
  fi
  popd
  rm -rf lists lists-packaged
  popd
fi # CODE_SIGNING_REQUIRED == NO

rm -rf "${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/apt"
rm -f "${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/"*.deb
rsync -a "${SOURCE_ROOT}/apt" "${SOURCE_ROOT}/Undecimus/resources/"* "${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/"

pushd "${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/apt"
dpkg-scanpackages . > Packages
cd ..
# Make sure these files exist and there is only one of them
ln -s apt/jailbreak-resources_*.deb resources.deb
popd

RESOURCES_VERSION="$(dpkg --info ${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/resources.deb | grep Version: | awk '{print $2}')"
if [ -z "${RESOURCES_VERSION}" ]; then
    echo "dpkg not found or resources.deb missing"
    exit 1
else
    echo "Bundled resources: ${RESOURCES_VERSION}"
fi

PACKAGE_VERSION="$(git describe --tags --match="v*" | sed -e 's@-\([^-]*\)-\([^-]*\)$@+\1.\2@;s@^v@@;s@%@~@g')"
if [ -z "${PACKAGE_VERSION}" ]; then
    echo "Could not generate package version"
    exit 1
else
    echo "Package Version: ${PACKAGE_VERSION}"
fi

defaults write "${TARGET_BUILD_DIR}/${INFOPLIST_PATH}" BundledResources "${RESOURCES_VERSION}"
defaults write "${TARGET_BUILD_DIR}/${INFOPLIST_PATH}" CFBundleShortVersionString "${PACKAGE_VERSION}"
