## DO NOT USE
if [ "$majoros" = "9" ]; then
    echo ${red}"Sorry, but this installer only works on Rocky 9.X ${textreset}"
    echo "Please upgrade to ${green}Rocky 9.x${textreset}"
    echo "Exiting the installer..."
    exit
else
    echo ${green}"Version information matches..Continuing${textreset}"
fi

#Checking for user permissions
if [ "$user" = "root" ]; then
    echo ${red}"This program must be run as root ${textreset}"
    echo "Exiting"
    exit
else
    echo "Running Program"
fi

cat <<EOF
This Installer will provide a GUI Driven menu for interacting with your system.
You can disable it, or not use it at all if you are comfortable with CLI.
However, there are scripts that have been written to assist you in AD management
and DHCP Management


The installer will continue shortly
EOF

sleep 10
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
/usr/bin/server-manager
