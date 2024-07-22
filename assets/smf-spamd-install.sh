#!/bin/bash

softname="smf-spamd"

BUILD_HOST="ghost-build"
CDN_HOST="tit-cdn.fumlersoft.dk"
CDN_USER="cdnuser"

get_cdn_filename () {
	echo "ls -1 ${softname}" | sftp -q ${CDN_USER}@${CDN_HOST} | tail -n1
}

get_installed_filename () {
	ls -1 /var/log/packages/${softname}*
	# | sed -En "s/.*${softname}-([0-9]+\.[0-9]+\.[0-9]+).*$/\1/p"
}

get_version() {
	echo $1  | sed -En "s/.*${softname}-([0-9]+\.[0-9]+\.[0-9]+).*$/\1/p"
}

CDN_FILE=$(get_cdn_filename)
CDN_VERSION=$(get_version ${CDN_FILE})

FILE=$(get_installed_filename)
VERSION=$(get_version ${FILE})

echo "${WHITE}$(basename ${CDN_FILE}) : ${GRAY}${CDN_FILE} ${RESTORE}"
echo "${WHITE}$(basename ${FILE}) : ${GRAY}${FILE} ${RESTORE}"

if [ -z ${VERSION} ]; then
	echo "=>${WHITE} No installed version. Installing new ${GREEN}${softname}-${CDN_VERSION}${RESTORE}"
elif [ "${VERSION}" != "${CDN_VERSION}" ]; then
	echo "=>${WHITE} Upgrading ${RED}${softname}-${VERSION}${WHITE} to ${GREEN}${softname}-${CDN_VERSION}${RESTORE}"
fi
