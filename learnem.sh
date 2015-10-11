#!/bin/sh

for d in /home/*; do
    [ -d $d/.bogofilter ] || continue

    # Process spam
    for f in `ls $d/Maildir/.LearnSPAM/new` `ls $d/Maildir/.LearnSPAM/cur`; do
	echo spam $f # SAM DBG
	bogofilter -Ns -I $f -d $d/.bogofilter
	mv $f ../../.Spam/new
    done

    # Process ham
    for f in `ls $d/Maildir/.Ham/new` `ls $d/Maildir/.Ham/cur`; do
	echo ham $f # SAM DBG
	bogofilter -Sn -I $f -d $d/.bogofilter
	rm $f
    done
done
