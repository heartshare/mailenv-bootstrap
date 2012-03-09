#!/bin/sh
apt-get update
apt-get install debconf-utils
echo -n "Enter your server's hostname [default: `hostname --fqdn`]: "
read I_HOSTNAME
if [ "$I_HOSTNAME" = "" ]
then
  I_HOSTNAME=`hostname --fqdn`
fi
I_DOMAIN=`hostname -d`
if [ "$I_DOMAIN" = "" ]
then
    $I_DOMAIN="localhost"
fi
echo -n "Enter your mail name [default: ${I_HOSTNAME}]: "
read I_MAILNAME
if [ "$_MAILNAME" = "" ]
then
  I_MAILNAME=$I_HOSTNAME
fi
I_POSTFIX_DESTINATIONS="${I_MAILNAME}, localhost.${I_DOMAIN}, localhost.localdomain, localhost"

# Postfix
cat >"/tmp/mail-server-installer-postfix" <<EOF
postfix	postfix/rfc1035_violation	boolean	false
postfix	postfix/mydomain_warning	boolean
postfix	postfix/mynetworks	string	127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
postfix	postfix/mailname	string	${I_MAILNAME}
postfix	postfix/tlsmgr_upgrade_warning	boolean
postfix	postfix/recipient_delim	string	+
postfix	postfix/main_mailer_type	select	Internet Site
postfix	postfix/destinations	string	${I_POSTFIX_DESTINATIONS}
postfix	postfix/retry_upgrade_warning	boolean
postfix	postfix/kernel_version_warning	boolean
postfix	postfix/not_configured	error
postfix	postfix/mailbox_limit	string	0
postfix	postfix/relayhost	string
postfix	postfix/procmail	boolean	false
postfix	postfix/bad_recipient_delimiter	error
postfix	postfix/protocols	select	ipv4
postfix	postfix/chattr	boolean	false
EOF
chmod 0644 "/tmp/mail-server-installer-postfix"
apt-get install -y postfix
rm /tmp/mail-server-installer-postfix
cp /etc/postfix/main.cf /etc/postfix/main.orig.cf
cat >/etc/postfix/main.cf <<EOF
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no

append_dot_mydomain = no

readme_directory = no

message_size_limit = 10240000

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/${I_MAILNAME}.crt
smtpd_tls_key_file=/etc/ssl/private/${I_MAILNAME}.key
smtpd_use_tls=yes
smtpd_tls_auth_only = no
smtpd_tls_security_level = encrypt
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtpd_helo_required = yes
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_exclude_ciphers = aNULL, MD5
smtpd_tls_mandatory_protocols = SSLv3, TLSv1
smtpd_tls_loglevel = 1

home_mailbox = .Maildir/
myhostname = ${I_MAILNAME}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = ${I_POSTFIX_DESTINATIONS}
relayhost = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 174.143.242.176/32
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all

smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
broken_sasl_auth_clients = yes

content_filter = scan:127.0.0.1:10025
receive_override_options = no_address_mappings

# DKIM & DK
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:12345 inet:localhost:12346
non_smtpd_milters = inet:localhost:12345 inet:localhost:12346


smtpd_sender_restrictions = permit_sasl_authenticated,
                                permit_mynetworks,


smtpd_recipient_restrictions = permit_mynetworks,
                                permit_sasl_authenticated,
                                reject_unauth_destination,
                                reject_unknown_sender_domain,
                                check_sender_access hash:/etc/postfix/sender_access
                                check_policy_service unix:private/policy-spf

spf-policyd_time_limit = 3600s
EOF
cp /etc/postfix/master.cf /etc/postfix/master.orig.cf
cat >/etc/postfix/master.cf <<EOF
smtp      inet  n       -       -       -       -       smtpd
        -o content_filter=spamassassin
        -o strict_rfc821_envelopes=yes
submission inet n       -       -       -       -       smtpd
	-o smtpd_tls_security_level=encrypt
	-o smtpd_sasl_auth_enable=yes
	-o smtpd_client_restrictions=permit_sasl_authenticated,reject
	-o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       -       -       -       smtpd
	-o smtpd_tls_wrappermode=yes
	-o smtpd_sasl_auth_enable=yes
	-o smtpd_client_restrictions=permit_sasl_authenticated,reject
	-o milter_macro_daemon_name=ORIGINATING
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
	-o smtp_fallback_relay=
        -o smtp_helo_timeout=5 -o smtp_connect_timeout=5
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
spamassassin unix -     n       n       -       -       pipe
        user=spamd argv=/usr/bin/spamc -f -e
        /usr/sbin/sendmail -oi -f \${sender} \${recipient}
policy-spf  unix  -       n       n       -       -       spawn
	user=nobody argv=/usr/bin/policyd-spf
scan      unix  -       -       n       -       16      smtp
        -o smtp_send_xforward_command=yes
127.0.0.1:10026 inet  n -       n       -       16      smtpd
        -o content_filter=
        -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
        -o smtpd_helo_restrictions=
        -o smtpd_client_restrictions=
        -o smtpd_sender_restrictions=
        -o smtpd_enforce_tls=no
        -o smtpd_recipient_restrictions=permit_mynetworks,reject
        -o mynetworks_style=host
        -o smtpd_authorized_xforward_hosts=127.0.0.0/8
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d \${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t\$nexthop -f\$sender $recipient
scalemail-backend unix	-	n	n	-	2	pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store \${nexthop} \${user} \${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  \${nexthop} \${user}
EOF

# Dovecot
apt-get install -y dovecot-imapd
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.orig.conf
cat >/etc/dovecot/dovecot.conf <<EOF
protocols = imap imaps

protocol imap {
	listen = *:143
	ssl_listen = *:993
}

log_timestamp = "%Y-%m-%d %H:%M:%S "

mail_location = maildir:~/.Maildir
mail_privileged_group = mail

protocol imap {
}

auth default {
	mechanisms = plain login

	passdb pam {
	}

	userdb passwd {
	}

	socket listen {
		client {
			path = /var/spool/postfix/private/auth
			mode = 0660
			user = postfix
			group = postfix
		}
	}
}

dict {
}

plugin {
}
EOF
chmod 0644 /etc/dovecot/dovecot.conf

# SASL
apt-get install -y sasl2-bin libsasl2-2 libsasl2-modules
cp /etc/default/saslauthd /etc/default/saslauthd.orig
cat >/etc/default/saslauthd <<EOF
START=yes
DESC="SASL Authentication Daemon"
NAME="saslauthd"
MECHANISMS="pam"
MECH_OPTIONS=""
THREADS=5
OPTIONS="-c -m /var/run/saslauthd"
EOF
chmod 0644 /etc/default/saslauthd
rm -r /var/run/saslauthd/
mkdir -p /var/spool/postfix/var/run/saslauthd
ln -s /var/spool/postfix/var/run/saslauthd /var/run
chgrp sasl /var/spool/postfix/var/run/saslauthd
adduser postfix sasl

# SpamAssassin
apt-get install -y spamassassin
groupadd -g 5001 spamd
useradd -u 5001 -g spamd -s /usr/sbin/nologin -d /var/lib/spamassassin spamd
mkdir /var/lib/spamassassin
chown spamd:spamd /var/lib/spamassassin
cp /etc/default/spamassassin /etc/default/spamassassin.orig
cat >/etc/default/spamassassin <<EOF
ENABLED=1
SAHOME="/var/lib/spamassassin/"
OPTIONS="--create-prefs --max-children 5 --username spamd --helper-home-dir ${SAHOME} -s /var/log/spamd.log"
PIDFILE="${SAHOME}spamd.pid"
PIDFILE="/var/run/spamd.pid"
CRON=1
EOF
chmod 0644 /etc/default/spamassassin
cp /etc/spamassassin/local.cf /etc/spamassassin/local.orig.cf
cat >/etc/spamassassin/local.cf <<EOF
rewrite_header Subject ***** SPAM _SCORE_ *****
report_safe 1

use_bayes 1
use_bayes_rules 1

bayes_auto_learn 1

razor_config /etc/mail/spamassassin/.razor/razor-agent.conf

pyzor_options --homedir /etc/mail/spamassassin
EOF
chmod 0644 /etc/spamassassin/local.cf

# ClamAV
apt-get install -y clamsmtp clamav-freshclam
cp /etc/clamsmtpd.conf /etc/clamsmtpd.orig.conf
cat >/etc/clamsmtpd.conf <<EOF
OutAddress: 10026
Listen: 127.0.0.1:10025

ClamAddress: /var/run/clamav/clamd.ctl
TempDirectory: /var/spool/clamsmtp
PidFile: /var/run/clamsmtp/clamsmtpd.pid
User: clamsmtp
EOF
chmod 0644 /etc/clamsmtpd.conf

# Procmail
apt-get install -y procmail
cp /etc/procmail /etc/procmail.orig
cat >/etc/procmail <<EOF
DROPPRIVS=YES
ORGMAIL=$HOME/.Maildir/
MAILDIR=$ORGMAIL
DEFAULT=$ORGMAIL
VERBOSE=yes
EOF
chmod 0644 /etc/procmail

# DK/DKIM
openssl genrsa -out private.key 1024
openssl rsa -in private.key -out public.key -pubout -outform PEM
mkdir /etc/dk/
cp private.key /etc/dk/dk.key
apt-get install -y dkim-filter dk-filter
# TODO: configuration

# SPF
apt-get install -y postfix-policyd-spf-python

# Razor
apt-get install -y razor
razor-admin -home=/etc/spamassassin/.razor -register
razor-admin -home=/etc/spamassassin/.razor -create
razor-admin -home=/etc/spamassassin/.razor -discover
razor_config /etc/spamassassin/.razor/razor-agent.conf

# Pyzor
apt-get install -y pyzor
pyzor discover
pyzor_options --homedir /etc/spamassassin




#apt-get purge -f debconf-utils
