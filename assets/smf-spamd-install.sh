#!/bin/bash

softname="smf-spamd"

BUILD_HOST="ghost-build"
CDN_HOST="tit-cdn.fumlersoft.dk"
CDN_USER="cdnuser"
ARCH=$(uname -m)

os_version=$(cat /etc/slackware-version | cut -f2 -d' ')
if [[ ${os_version} == *"+" ]]; then
  os_version="current"
fi
if [ "${os_version}" = "" ]; then
	os_version="unknown"
fi

PACK="${HOME}/local/packages"
INST="/var/log/packages"

get_cdn_filename () {
	echo "ls -1 ${softname}" | sftp -q ${CDN_USER}@${CDN_HOST} | sort -V | tail -n1
}

get_local_filename () {
	ls -1 ${PACK}/${softname}-* | sort -V | tail -n1
}

get_installed_filename () {
	ls -1 ${INST}/${softname}* | sort -V | tail -n1
	# | sed -En "s/.*${softname}-([0-9]+\.[0-9]+\.[0-9]+).*$/\1/p"
}

get_version() {
	echo $1  | sed -En "s/.*${softname}-([0-9]+\.[0-9]+\.[0-9]+).*$/\1/p"
}

get_tag() {
	echo $1  | sed -En "s/.*-${os_version}-([0-9]+)(\.txz)?$/\1/p"
}

install_new() {
	echo "Installing ${softname} ${1}..."
	upgradepkg --install-new ${1}
}

upgrade() {
	echo "${WHITE}Upgrading ${softname} from ${RED}${1}${WHITE} to ${GREEN}${2}${RESTORE}"
	upgradepkg ${1}%${2}
}

download() {
	echo "${WHITE}Downloading${YELLOW} ${softname}${CYAN} ${CDN_USER}@${CDN_HOST}:${1} ${RESTORE}..."
	sftp -q ${CDN_USER}@${CDN_HOST}:${1} ${PACK}/ \
	|| { echo "${RED} downloading ${1} failed..${RESTORE}"; exit 1; }

	echo "${WHITE}* Refresh local: ${GREEN}${softname}${RESTORE}"
	PACK_FILE=$(get_local_filename)

	PACK_VERSION=$(get_version ${PACK_FILE})
	PACK_VERSION_TAG=$(get_tag ${PACK_FILE})
}

echo "${WHITE}* Checking on CDN: ${GREEN}${softname}${RESTORE}"
CDN_FILE=$(get_cdn_filename)

CDN_VERSION=$(get_version ${CDN_FILE})
CDN_VERSION_TAG=$(get_tag ${CDN_FILE})

echo "${WHITE}* Checking for local: ${GREEN}${softname}${RESTORE}"
PACK_FILE=$(get_local_filename)

PACK_VERSION=$(get_version ${PACK_FILE})
PACK_VERSION_TAG=$(get_tag ${PACK_FILE})

echo "${WHITE}* Checking on installed: ${GREEN}${softname}${RESTORE}"
INST_FILE=$(get_installed_filename)

VERSION=$(get_version ${INST_FILE})
VERSION_TAG=$(get_tag ${INST_FILE})

if [ "$(basename ${PACK_FILE})" != "$(basename ${CDN_FILE})" ]; then
	echo "=>${WHITE} Downloading new ${GREEN}${CDN_FILE}${RESTORE}"
	download ${CDN_FILE}
fi

echo "${BLUE}CDN version........:${WHITE} $(basename ${CDN_FILE}) : ${YELLOW}${CDN_VERSION} ${CDN_VERSION_TAG} ${RESTORE}"
echo "${BLUE}Local version......:${WHITE} $(basename ${PACK_FILE}) : ${YELLOW}${PACK_VERSION} ${PACK_VERSION_TAG} ${RESTORE}"
echo "${BLUE}Installed version..:${WHITE}  $(basename ${INST_FILE}) : ${YELLOW}${VERSION} ${VERSION_TAG} ${RESTORE}"

VERSION="${VERSION}-${VERSION_TAG}"
CDN_VERSION="${CDN_VERSION}-${CDN_VERSION_TAG}"

if [ -z ${VERSION} ]; then
	echo "=>${WHITE} No installed version. Installing new ${GREEN}${softname}-${PACK_FILE}${RESTORE}"
	install_new ${PACK_FILE}
elif [ "${VERSION}" != "${CDN_VERSION}" ]; then
	echo "=>${WHITE} Upgrading ${RED}${softname}-${VERSION}${WHITE} to ${GREEN}${softname}-${CDN_VERSION}${RESTORE}"
	upgrade "$(basename ${INST_FILE})" "${PACK_FILE}"
fi
