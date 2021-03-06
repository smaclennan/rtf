# RTF - Really Trivial Filter

This directory contains two sets of programs:

1. The original rtf + friends
2. imap-rtf + friends

## rtf

The original rtf was used when I had my own mail server. It was meant
to deal with spam and do folder filtering. I used rtf for years but,
now that I have moved to the cloud, I no longer need it.

## imap-rtf

imap-rtf is meant almost exclusively to deal with folders. It still
has a blacklist and whitelist, but it is the folders which are most
useful.

The idea is that, rather than setting up filters in every imap client
you run, you run imap-rtf and let it deal with filtering. It also
helps for clients with less than optimal, or no, filtering.

clean-imap is a companion program that is meant to run from cron
(although you don't have to). It allows deleting old messages from
folders.

### BearSSL

Currently the imap-rtf code requires BearSSL. If you have BearSSL
built somewhere... you can point the Makefile at that directory.

For everybody else, BearSSL is a submodule of rtf. Just enter the
following commands:

    git submodule init
    git submodule update

#### Certificate files

imap-rtf will run with 0 or more cert files. Every file in .rtf.d that
starts with cert* will be added to the chain. You should have at least
two: one from the server and the trusted root.

On Slackware, Ubuntu, and probably most others, the trusted certs are
in /etc/ssl/certs. I linked the needed cert into ~/.rtf.d as
cert-root. A good way to test the certs is with brssl provided by
BearSSL. In my case:

    brssl verify -CA ~/.rtf.d/cert-root ~/.rtf.d/cert
