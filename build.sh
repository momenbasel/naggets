#!/usr/bin/env bash
set -e

#
# Note: It is assumed that the build script will be run as the root user.
#

echo "[+] Building nuggets"
echo "[+] OS: Ubuntu 14.04 LTS"
echo "[+] Author: 0xmmn"
echo "[+] Date: 2020-11-02"
echo "[+] Point Value: 20"

echo "[+] Installing utilities"
apt install -y net-tools vim open-vm-tools

echo "[+] Configuring first vector"
echo "[+] Installing Apache and PHP"
apt install -y apache2 libapache2-mod-php
echo "[+] Installing dependencies and python"
apt install python3 python3-pip python-pip wget -y
pip3 install selenium
apt install chromium-chromedriver chromium-browser  -y
echo "[+] Creating vulnerable website"
wget https://assets.nagios.com/downloads/nagiosxi/5/xi-5.5.6.tar.gz
tar -xvf xi-5.5.6.tar.gz
cd nagiosxi
chmod 777 *
sudo ./fullinstall  -n
rm -rf /var/www/html/index.html

mv setup.py ~/setup.py

echo "[+] Enabling Apache"
systemctl enable apache2
systemctl start apache2


echo "[+] installing rabbitholes"
sudo apt-get -y install exim4 sendmail

echo "[+] Configuring firewall"
echo "[+] Installing iptables"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
apt install -y iptables-persistent

#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that inbound ICMP and SSH on port 22 are permitted.
#

echo "[+] Applying inbound firewall rules"
iptables -I INPUT 1 -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A INPUT -j DROP

#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that outbound ICMP, DNS (TCP & UDP) on port 53 and SSH on port 22
#       are permitted.
#

echo "[+] Applying outbound firewall rules"
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A OUTPUT -j DROP

echo "[+] Saving firewall rules"
service netfilter-persistent save

echo "[+] Disabling IPv6"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"/' /etc/default/grub
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' /etc/default/grub
update-grub

echo "[+] Configuring hostname"
hostnamectl set-hostname nuggets
cat << EOF > /etc/hosts
127.0.0.1 localhost
127.0.0.1 cookies
EOF

echo "[+] Creating users if they don't already exist"
id -u cookies &>/dev/null || useradd -m cookies
usermod -aG sudo cookies
id -u rasta &>/dev/null || useradd -m rasta
usermod -aG sudo rasta
echo "[+] Privilage escalation"
sudo apt install vi vim -y
sudo echo 'cookies ALL = NOPASSWD:/bin/vim,/bin/vi' >> /etc/sudoers

echo "[+] Disabling history files"
ln -sf /dev/null /root/.bash_history
ln -sf /dev/null /home/cookies/.bash_history

#
# Note: Unless specifically required as part of the exploitation path, please
#       ensure that root login via SSH is permitted.
#

echo "[+] Enabling root SSH login"
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

echo "[+] Setting passwords"
echo "root:hardandstrongpasswordthatyoucantguessevenifyourcatishappy" | chpasswd
echo "cookies:cookies" | chpasswd

echo "[+] Dropping flags"
echo "f411d87894b17b94b2df0c612fc978d9" > /root/proof.txt
echo "eb0d623fa3ebf4ab0c39a9495198eaca" > /home/cookies/local.txt
chmod 0600 /root/proof.txt
chmod 0644 /home/cookies/local.txt
chown cookies:cookies /home/cookies/local.txt

#
# Note: Please ensure that any artefacts and log files created by the build script or
#       while running the build script are removed afterwards.
#

echo "[+] Cleaning up"
rm -rf /root/build.sh
rm -rf /root/.cache
rm -rf /root/.viminfo
rm -rf /home/cookies/.sudo_as_admin_successful
rm -rf /home/cookies/.cache
rm -rf /home/cookies/.viminfo
rm -rf ~/setup.py
find /var/log -type f -exec sh -c "cat /dev/null > {}" \;
