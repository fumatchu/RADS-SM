#!/bin/sh
#RADS-SMINstall.sh
#This script installs a set of scripts for AD/DHCP Management

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
USER=$(whoami)
MAJOROS=$(cat /etc/redhat-release | grep -Eo "[0-9]" | sed '$d')

#Checking for user permissions
if [ "$USER" = "root" ]; then
echo " "
else
  echo ${RED}"This program must be run as root ${TEXTRESET}"
  echo "Exiting"
fi
#Checking for version Information
if [ "$MAJOROS" = "9" ]; then
echo " "
else
  echo ${RED}"Sorry, but this installer only works on Rocky 9.X ${TEXTRESET}"
  echo "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET}"
  echo "Exiting the installer..."
  exit
fi

cat <<EOF
${GREEN}Installing Server Management${TEXTRESET}
This Installer will provide a set of scripts wrapped in a dialog GUI
You will be able to manage components of AD, DHCP and services
At Anytime from the cLI, type ${YELLOW}server-manager${TEXTRESET}


The installer will continue shortly
EOF

sleep 7
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
cd; cd -
/usr/bin/server-manager
