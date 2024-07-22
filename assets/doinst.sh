config() {
  NEW="$1"
  OLD="$(dirname $NEW)/$(basename $NEW .new)"
  # If there's no config file by that name, mv it over:
  if [ ! -r $OLD ]; then
    mv $NEW $OLD
  elif [ "$(cat $OLD | md5sum)" = "$(cat $NEW | md5sum)" ]; then
    # toss the redundant copy
    rm $NEW
  fi
  # Otherwise, we leave the .new copy for the admin to consider...
}

preserve_perms() {
  NEW="$1"
  OLD="$(dirname $NEW)/$(basename $NEW .new)"
  if [ -e $OLD ]; then
    cp -a $OLD ${NEW}.incoming
    cat $NEW > ${NEW}.incoming
    mv ${NEW}.incoming $NEW
  fi
  config $NEW
}

getent group smfs > /dev/null \
|| {
	echo "${WHITE}* Adding group ${YELLOW}smfs${RESTORE}"
	groupadd -r -g 239 smfs || exit 1
}

getent passwd smfs > /dev/null \
|| {
	echo "${WHITE}* Adding user ${YELLOW}smfs${RESTORE}"
	useradd -r -d /dev/null -s /bin/false -u 239 -g 239 smfs || exit 1
}

mkdir -m 750 -p /var/run/smfs
chown -R smfs:smfs /var/run/smfs

preserve_perms etc/rc.d/rc.smf-spamd.new
if [ -f etc/smfs/smf-spamd.conf.new ]; then
  config etc/mail/smfs/smf-spamd.conf.new
fi

slackpack new-config