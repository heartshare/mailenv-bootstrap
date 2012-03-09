=================
mailenv-bootstrap
=================

*THIS IS CURRENTLY ONLY A TEST SCRIPT*
*IT HAS NOT BEEN TESTED*

*DO NOT USE IT*

This is a single bootstrap shell file for Debian 5 and 6 and Ubuntu 10.04 - 12.04 operating
systems.

The bootstrap.sh file will install and configure your mail environment for you.

Packages
========

What is installed
* Postfix
* Dovecot (IMAP/IMAPS only)
* SASL (for authentication against PAM)
* SpamAssassin (for spam protection)
* ClamAV (for anti-virus scanning of emails inbound and outbound)
* Procmail (for local delivery and filtering)
* DKIM (using dkim-filter)
* DomainKeys (using dk-filter)
* SPF
* Razor
* Pyzor

Usage
=====
::
  sh bootstrap.sh

When asked for input, you will need to provide it. But the installer only asks for a few pieces
of information
