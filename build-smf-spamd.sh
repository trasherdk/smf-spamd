#!/usr/bin/bash

BASE=$(realpath "$(dirname "$0")")
cd ${BASE}

BUILD_HOST="ghost-build"
CDN_HOST="tit-cdn.fumlersoft.dk"
CDN_USER="cdnuser"

softname='smf-spamd'
version=${1:-'1.3.6'}
build=2
os_version=$(cat /etc/slackware-version | cut -f2 -d' ')
if [[ ${os_version} == *"+" ]]; then
  os_version="current"
fi
if [ "${os_version}" = "" ]; then
	os_version="unknown"
fi

echo "* Automatically determine the architecture we're building on:"

ARCH=$( uname -m )
case "${ARCH}" in
	i?86) ARCH=i686 ;;
	arm*) readelf /usr/bin/file -A | grep -E -q "Tag_CPU.*[4,5]" && ARCH=arm || ARCH=armv7hl ;;
	# Unless ${ARCH} is already set, use uname -m for all other archs:
	*) ARCH=$(uname -m) ;;
esac
export ARCH

echo "ARCH is $ARCH"

echo "* Set CFLAGS/CXXFLAGS and LIBDIRSUFFIX:"
case "${ARCH}" in
  i?86)		SLKCFLAGS="-O2 -march=${ARCH} -mtune=i686"
            SLKLDFLAGS=""; LIBDIRSUFFIX=""
            SRC_ARCH="x86"
            ;;
  x86_64)	SLKCFLAGS="-O2 -fPIC"
            SLKLDFLAGS="-L/usr/lib64"; LIBDIRSUFFIX="64"
            SRC_ARCH="x64"
            ;;
  *)		SLKCFLAGS=${SLKCFLAGS:-"-O2"}
            SLKLDFLAGS=${SLKLDFLAGS:-""}; LIBDIRSUFFIX=${LIBDIRSUFFIX:-""}
            ;;
esac

case "${ARCH}" in
    arm*)	TARGET=${ARCH}-slackware-linux-gnueabi ;;
    *)		TARGET=${ARCH}-slackware-linux ;;
esac

echo "BASE is..........: ${BASE}"
echo "TARGET is........: ${TARGET}"
echo "LIBDIRSUFFIX is..: ${LIBDIRSUFFIX}"

sourcedir=${softname}
packagedir=${softname}-${version}-${ARCH}-${os_version}-${build}

#rm -fr ${BASE}/${softname}*
echo -n "Remove old stuff: ${BASE}/${softname}-*"
rm -fr "${BASE}/${softname}-*" \
&& { echo "${LGREEN} OK ${RESTORE}"; } \
|| { echo "${RED} FAIL ${RESTORE}"; }

#if [ -f ${BASE}/packages/${softname}-${version}.tar.gz ]; then
#	tar xvf ${BASE}/packages/${softname}-${version}.tar.gz
#else
#	echo "${RED} Archive not found: ${YELLOW}${softname}-${version}${RESTORE}"
#	exit 1
#fi

cd "${BASE}/${sourcedir}" || exit 1

chown -R root:root .

make clean && make || exit 1

mkdir -p ${BASE}/${packagedir}/usr/local/sbin
cp -a ${softname} ${BASE}/${packagedir}/usr/local/sbin/

#mkdir -p ${BASE}/${packagedir}/var/run/smfs

#mkdir -p ${BASE}/${packagedir}/etc/mail/smfs
#cp -a ${BASE}/assets/${softname}.conf ${BASE}/${packagedir}/etc/mail/smfs/${softname}.conf.new

mkdir -p ${BASE}/${packagedir}/etc/rc.d
cp -a ${BASE}/assets/rc.${softname} ${BASE}/${packagedir}/etc/rc.d/rc.${softname}.new

mkdir -p ${BASE}/${packagedir}/usr/local/sbin || exit 1
cp ${BASE}/assets/smf-spamd-install.sh ${BASE}/${packagedir}/usr/local/sbin/

mkdir -p "${BASE}/${packagedir}/usr/doc/${softname}-${version}"
cp -ra ${BASE}/$(basename $0) contrib init COPYING ChangeLog readme \
	"${BASE}/${packagedir}/usr/doc/${softname}-${version}/"

echo "* Creating install script...."
mkdir -p "${BASE}/${packagedir}/install"

if [ -f "${BASE}/assets/slack-desc" ]; then
	cat "${BASE}/assets/slack-desc" > "${BASE}/${packagedir}/install/slack-desc"
fi

cp "${BASE}/assets/doinst.sh" "${BASE}/${packagedir}/install/"

cd "${BASE}/${packagedir}" || exit 1

echo "* setting permisions on files and directories...."

find -L . \
 \( -perm 777 -o -perm 775 -o -perm 750 -o -perm 711 -o -perm 555 \
  -o -perm 511 \) -exec chmod 755 {} \; -o \
 \( -perm 666 -o -perm 664 -o -perm 640 -o -perm 600 -o -perm 444 \
  -o -perm 440 -o -perm 400 \) -exec chmod 644 {} \;

echo "* Stripping unneeded stuff from files...."
find . -print0 | xargs file | grep "executable" | grep ELF | cut -f 1 -d : | xargs strip --strip-unneeded 2> /dev/null
find . -print0 | xargs file | grep "shared object" | grep ELF | cut -f 1 -d : | xargs strip --strip-unneeded 2> /dev/null

echo "* Creating the installer package...."
cd "${BASE}/${packagedir}" || exit 1
makepkg -l y -c n "${BASE}/${packagedir}.txz"

cd "${BASE}" || exit 1

if [ ! -d "${BASE}/packages/${softname}-${version}.tar.gz" ]; then
  echo "* Save source in ${softname}-${version}.tar.gz"
  tar czvf "${BASE}/packages/${softname}-${version}.tar.gz" "./${softname}"
fi

echo -n "* Create CDN directory on: "
if [ "$(hostname -s)" = "${BUILD_HOST}" ]; then
  echo "${BUILD_HOST}"
  if [ ! -d "/home/${CDN_USER}/files/${softname}" ]; then
    mkdir "/home/${CDN_USER}/files/${softname}"
  fi
  chgrp -R ${CDN_USER} "/home/${CDN_USER}/files/${softname}"
  chmod -R g+w "/home/${CDN_USER}/files/${softname}"
else
  echo "${CDN_HOST}"
  ssh ${CDN_HOST} "[ ! -d /home/${CDN_USER}/files/${softname} ] && mkdir /home/${CDN_USER}/files/${softname}"
  ssh ${CDN_HOST} "chgrp -R ${CDN_USER} /home/${CDN_USER}/files/${softname}"
  ssh ${CDN_HOST} "chmod -R g+w /home/${CDN_USER}/files/${softname}"
fi

echo "* Uploading to CDN: ${CDN_HOST}"
echo "put ${packagedir}.txz ${softname}/" | sftp ${CDN_USER}@${CDN_HOST} \
|| { echo "${RED} uploading ${packagedir}.txz failed..${RESTORE}"; exit 1; }

echo "* Move ${packagedir}.txz to ./packages"
mv ${packagedir}.txz ./packages/ || exit 1

echo "${LGREEN}*** All done ***${RESTORE}"
exit 0
