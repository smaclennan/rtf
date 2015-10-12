#!/bin/sh

for d in /home/*; do
    [ -d $d/.bogofilter ] || continue
	
    # Process spam
	bogofilter -Ns -d $d/.bogofilter -B $d/Maildir/.LearnSPAM
	if [ -n "`ls $d/Maildir/.LearnSPAM/cur`" ]; then
		mv $d/Maildir/.LearnSPAM/cur/* $d/Maildir/.Spam/cur
	fi
	if [ -n "`ls $d/Maildir/.LearnSPAM/new`" ]; then
		mv $d/Maildir/.LearnSPAM/new/* $d/Maildir/.Spam/new
	fi

    # Process ham
	bogofilter -Sn -d $d/.bogofilter -B $d/Maildir/.Ham
	rm -f $d/Maildir/.Ham/cur/*
	rm -f $d/Maildir/.Ham/new/*
done
