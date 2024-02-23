#!/bin/sh
#RADS-SMINstall.sh
#This script installs a set of scripts for AD/DHCP Management

if [ "$majoros" = "9" ]; then
    echo ${red}"Sorry, but this installer only works on Rocky 9.X ${textreset}"
    echo "Please upgrade to ${green}Rocky 9.x${textreset}"
    echo "Exiting the installer..."
    exit
else
    echo " "
fi

#Checking for user permissions
if [ "$user" = "root" ]; then
    echo ${red}"This program must be run as root ${textreset}"
    echo "Exiting"
    exit
else
    echo " "
fi

cat <<EOF
${GREEN}Installing Server Management${TEXTRESET}
This Installer will provide a set of scripts wrapped in a dialog GUI
you will be able to manage components of AD, DHCP and services with it


The installer will continue shortly
EOF

sleep 5
dnf -y install dialog nano htop iptraf-ng mc
rm -r -f /root/.servman
rm -f /usr/bin/server-manager
sed -i '/usr/bin/server-manager/d' /root/.bash_profile
cd /root/RADS-SMInstaller
mv -v ./.servman /root
chmod 700 /root/RADS-SMInstaller/server-manager
mv -v /root/RADS-SMInstaller/server-manager /usr/bin/
chmod -R 700 /root/.servman/
echo "/usr/bin/server-manager" >>/root/.bash_profile

rm -r -f /root/RADS-SMInstaller
rm -r -f /root/RADS-SMInstaller.sh
pkill dialog 
/usr/bin/server-manager
