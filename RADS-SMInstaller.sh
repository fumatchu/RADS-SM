#!/bin/sh
#RADS-SMInstaller.sh #Bootstrap to GIT REPO
cat <<EOF
**************************
Please wait while we gather some files
**************************


Installing wget and git
EOF
sleep 1

dnf -y install wget git 

cat <<EOF
*****************************
Retrieving Files from GitHub
*****************************
EOF

sleep 1

mkdir /root/RADS-SMInstaller

git clone https://github.com/fumatchu/RADS-SM.git /root/RADS-SMInstaller

chmod 700 /root/RADS-SMInstaller/RA*
clear

#/root/RADS-SMInstaller/RADS-SMInstall.sh
