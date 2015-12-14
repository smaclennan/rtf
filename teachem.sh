#!/bin/sh -e

[ -d $HOME/.bogofilter ] || exit 1
cd $HOME/Maildir || exit 1

# Process spam
bogofilter -Ns -d $HOME/.bogofilter -e -B .LearnSPAM
if [ -n "`ls .LearnSPAM/cur`" ]; then
    mv .LearnSPAM/cur/* .Spam/cur
fi
if [ -n "`ls .LearnSPAM/new`" ]; then
    mv .LearnSPAM/new/* .Spam/new
fi

# Process ham
bogofilter -Sn -d $HOME/.bogofilter -e -B .Ham
rm -f .Ham/cur/*
rm -f .Ham/new/*

exit 0
