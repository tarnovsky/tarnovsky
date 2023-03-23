RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

if [ "$USER" != "root" ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
fi

##############################################################################################

#apt-get update -y
#apt-get upgrade -y
#apt-get autoremove -y

##############################################################################################

echo
echo  "${BLUE}1${NC} Initial Setup - Secure Boot Settings${NC}"
echo
echo  "${RED}1.1${NC} Setting GRUB Bootloader Password"
grubpassword=$(cat templates/grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
echo " set superusers="root" " >> /etc/grub.d/40_custom
echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
echo  "${GREEN}Remediated:${NC} GRUB password set. Refer to README"
echo
echo  "${RED}1.2${NC} Setting GRUB Configurations"

cp templates/grub /etc/default/grub
update-grub
echo  "${GREEN}Remediated:${NC} GRUB configurations set"
echo
echo  "${RED}1.3${NC} Securing GRUB file permissions"
sleep 2
chown root:root /boot/grub/grub
chmod og-rwx /boot/grub/grub
echo  "${GREEN}Remediated:${NC} GRUB file permissions secured"

##############################################################################################

echo
echo  "${BLUE}2${NC} Initial Setup - Restricting UMASK${NC}"
cp templates/login.defs /etc/login.defs
echo  "${GREEN}Remediated:${NC} UMASK set to Restrictive Value (027)"

##############################################################################################

echo
echo  "${BLUE}3${NC} Initial Setup - Creating Admin User${NC}"
username="milton"
useradd -m $username 
echo "$username:zrX@Ez?piHSz1g~R$!Zk]e2c" | chpasswd
echo "$username ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
if [ ! -d '/home/$username/.ssh' ]
then
    mkdir /home/$username/.ssh
    chown $username:$username /home/$username/.ssh
    chmod 700 /home/$username/.ssh
fi
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCao5gbrOSBHaT+a5GC6vEFb5sZJb73bDf8wC7NkR4HB4Iwh3oOLufbTEVy4egIw2hBEuKJqD2FJ+b66OeF306OhUDl9EvYnTl0cJ2jz6Hj0bcJz/v0eH1iJC6F6xVU19dvibvcp8gOBa9hFhGadNHwHdXbd7XNDTQiZrwbhC3v2RFaGQoy7ODJA9u7LKh+8tAiTj2Ma9Ub0fSED6/YQP0XLZO/i1OL8CuYYutw8P5Zdv+lWmgZVr27Id8QoWbFSIVkoHqvmUTqOlGgl6MVgu+3rB0NqSKH4W6mj8HbthS7iC6EWGLXZAx0gR9JOHhxHQhBQl/1PlmNTaZNm0IKUCgvavExpxOBXxdcokAeR/tXmj0zjK7YIaOrl7wiBPSSwr+QVWumS9BQ9dV2vhw3LUkL8j0z0pP2NSbLssyxvo8JyVuEYevh4KLFA2kbMKrFn3Za01jVw+MFEWOp3tW9J10ycdoGbs2UTZkQZOmMwSz5/zwToLzN/ZWAkGvhuD5TS0= milton@ls23" >> /home/$username/.ssh/authorized_keys
chown $username:$username /home/$username/.ssh/authorized_keys
chmod 600 /home/$username/.ssh/authorized_keys
echo  "${GREEN}Remediated:${NC} User created. Copy private key in Git to your system in order to login in as user"

##############################################################################################

echo
echo  "${BLUE}4${NC} Initial Setup - Securing /tmp Folder${NC}"
dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000
mkdir /tmpbackup
cp -Rpf /tmp /tmpbackup
mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
chmod 1777 /tmp
cp -Rpf /tmpbackup/* /tmp/
rm -rf /tmpbackup
echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
sudo mount -o remount /tmp
echo  "${GREEN}Remediated:${NC} FileSystem created for the /tmp Directory and proper permissions set"


##############################################################################################

echo
echo  "${BLUE}5${NC} Initial Setup - Securing SSH${NC}"
cp templates/sshd_config /etc/ssh/ssh_config; echo "OK"
cp templates/sshd_config /etc/ssh/sshd_config; echo "OK"
service ssh restart
echo  "${GREEN}Remediated:${NC} SSH secured"

##############################################################################################

echo
echo  "${BLUE}6${NC} Initial Setup - Setting IPTABLE Rules${NC}"
sh templates/iptables.sh
cp templates/iptables.sh /etc/init.d/
chmod +x /etc/init.d/iptables.sh
ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
echo  "${GREEN}Remediated:${NC} IPTABLE script ran. Refer to README"

##############################################################################################

echo
echo  "${BLUE}7${NC} Initial Setup - Tuning and Securing the Linux Kernel${NC}"
echo "* hard core 0" >> /etc/security/limits.conf
cp templates/sysctl.conf /etc/sysctl.conf; echo " OK"
cp templates/ufw /etc/default/ufw
sysctl -e -p
echo  "${GREEN}Remediated:${NC} Linux Kernel Secure"

##############################################################################################

#echo
#echo  "${BLUE}8${NC} Initial Setup - Installing RootKit Hunter${NC}"
#echo "Rootkit Hunter is a scanning tool to ensure you are you're clean of nasty tools. This tool scans for rootkits, backdoors and local exploits by running tests like:
#      - MD5 hash compare
#      - Look for default files used by rootkits
#      - Wrong file permissions for binaries
#      - Look for suspected strings in LKM and KLD modules
#      - Look for hidden files
#      - Optional scan within plaintext and binary files "
#sleep 1
#cd rkhunter-1.4.6/
#sh installer.sh --layout /usr --install
#cd ..
#rkhunter --update
#rkhunter --propupd
#echo ""
#echo " ***To Run RootKit Hunter ***"
#echo "     rkhunter -c --enable all --disable none"
#echo "     Detailed report on /var/log/rkhunter.log"
#echo  "${GREEN}Remediated:${NC} RootKit Hunter Installed"

##############################################################################################

echo
echo  "${BLUE}9${NC} Initial Setup - Additional Hardening Processes${NC}"
echo
echo  "${RED}9.1${NC} Securing /etc/securetty"
echo tty1 > /etc/securetty
chmod 0600 /etc/securetty
echo  "${GREEN}Remediated:${NC} /etc/securetty secured with 0600"
echo
echo  "${RED}9.2${NC} Securing /root"
chmod 700 /root
echo  "${GREEN}Remediated:${NC} /root secured with 700"
echo
echo  "${RED}9.3${NC} Securing /boot/grub/grub.cfg"
chmod 600 /boot/grub/grub.cfg
echo  "${GREEN}Remediated:${NC} /boot/grub/grub.cfg secured with 600"
#Remove AT and Restrict Cron
echo
echo  "${RED}9.4${NC} Remove AT"
apt purge at
echo  "${GREEN}Remediated:${NC} AT removed"
echo
echo  "${RED}9.5${NC} Secure Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo  "${GREEN}Remediated:${NC} Cron Secured"
echo
echo  "${RED}9.6${NC} Disabling USB Support"
cp templates/DISASTIG.conf /etc/modprobe.d/DISASTIG.conf
update-initramfs -u
echo  "${GREEN}Remediated:${NC} USB Disabled"
#echo " Installing libpam-pkcs11"
#apt-get install libpam-pkcs11 -y
echo
echo  "${RED}9.7${NC} Installing vlock"
apt-get install vlock -y --force-yes
echo  "${GREEN}Remediated:${NC} vlock installed"
echo
echo  "${RED}9.8${NC} Disabling accounts after 35 days of activity"
useradd -D -f 35
echo  "${GREEN}Remediated:${NC} account settings updated"
echo
echo  "${RED}9.9${NC} Securing APT"
cp templates/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades
echo  "${GREEN}Remediated:${NC} APT Secured"
echo
echo  "${RED}9.10${NC} Limiting concurrent logins to 10"
cp templates/limits.conf /etc/security/limits.conf
echo  "${GREEN}Remediated:${NC} Number of logins limited"
echo
echo  "${RED}9.11${NC} Adding time display of last login to system"
echo "session required pam_lastlog.so showfailed" >> /etc/pam.d/login
echo  "${GREEN}Remediated:${NC} Time displayed"
echo
echo  "${RED}9.12${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo  "${GREEN}Remediated:${NC} ASLR enabled"
#Ensure prelink is disabled
echo
echo  "${RED}9.13${NC} Ensure prelink is disabled"
prelink -ua
apt-get remove prelink
echo  "${GREEN}Remediated:${NC} prelink disabled"

##############################################################################################

echo
echo  "${BLUE}10${NC} Initial Setup - Disabling Compilers${NC}"
chmod 000 /usr/bin/as >/dev/null 2>&1
chmod 000 /usr/bin/byacc >/dev/null 2>&1
chmod 000 /usr/bin/yacc >/dev/null 2>&1
chmod 000 /usr/bin/bcc >/dev/null 2>&1
chmod 000 /usr/bin/kgcc >/dev/null 2>&1
chmod 000 /usr/bin/cc >/dev/null 2>&1
chmod 000 /usr/bin/gcc >/dev/null 2>&1
chmod 000 /usr/bin/*c++ >/dev/null 2>&1
chmod 000 /usr/bin/*g++ >/dev/null 2>&1
echo  "${GREEN}Remediated:${NC} All common compilers disabled if existed"

##############################################################################################

echo
echo  "${BLUE}11${NC} Initial Setup - Increasing password complexity requirements${NC}"
apt-get install libpam-pwquality -y --force-yes
cp templates/pwquality.conf /etc/security/pwquality.conf
cp templates/common-password /etc/pam.d/common-password
echo  "${GREEN}Remediated:${NC} Password complexity set"

############################################################################################## 

echo
echo  "${BLUE}12${NC} Initial Setup - Configuring audit.rules${NC}"
apt-get install auditd -y --force-yes
systemctl enable auditd.service
cp templates/stig.rules /etc/audit/rules.d/stig.rules
cp templates/audit.rules /etc/audit/audit.rules
cp templates/auditd.conf /etc/audit/auditd.conf 
systemctl restart auditd
augenrules --load
echo  "${GREEN}Remediated:${NC} audit.rules set"

############################################################################################## 

echo
echo  "${BLUE}13${NC} Initial Setup - Ensure AIDE is installed${NC}"
apt-get install aide aide-common -y --force-yes
# aideinit && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

crontab -u root -e
egrep -q "^(\s*)aide\s+\S+(\s*#.*)?\s*$" /etc/crontab && sed -ri "s/^(\s*)aide\s+\S+(\s*#.*)?\s*$/\10 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\2/" /etc/crontab || echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab
echo  "${GREEN}Remediated:${NC} aide configured to ensure filesystem integrity"

############################################################################################## 

echo
echo  "${BLUE}14${NC} Initial Setup - Configuring faillock {NC}"
cp templates/common-auth /etc/pam.d/common-auth
cp templates/faillock.conf /etc/security/faillock.conf
echo  "${GREEN}Remediated:${NC} faillock configured"

############################################################################################## 

echo
echo  "${BLUE}15${NC} Initial Setup - Disabling mounts {NC}"
echo
echo  "${RED}15.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo  "${GREEN}Remediated:${NC} cramfs disabled"
echo
echo  "${RED}15.2${NC} Ensure mounting of jffs filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo  "${GREEN}Remediated:${NC} jffs disabled"
echo
echo  "${RED}15.3${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo  "${GREEN}Remediated:${NC} hfs disabled"
echo
echo  "${RED}15.4${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo  "${GREEN}Remediated:${NC} hfsplus disabled"
echo
echo  "${RED}15.5${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo  "${GREEN}Remediated:${NC} udf disabled"
echo
echo  "${RED}15.6${NC} Disable Automounting"
systemctl disable autofs.service
echo  "${GREEN}Remediated:${NC} automounting disabled"

############################################################################################## 

echo
echo  "${BLUE}16${NC} Initial Setup - Setting File Permissions on Critical System Files${NC}"
chmod -R g-wx,o-rwx /var/log/*

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

chown root:root /etc/group
chmod 644 /etc/group

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:shadow /etc/shadow && chmod o-rwx,g-wx /etc/shadow

chown root:root /etc/group
chmod 644 /etc/group

chown root:shadow /etc/gshadow && chmod o-rwx,g-wx /etc/gshadow

chown root:root /etc/passwd- && chmod u-x,go-wx /etc/passwd-

chown root:shadow /etc/shadow- && chmod o-rwx,g-rw /etc/shadow-

chown root:root /etc/group- && chmod u-x,go-wx /etc/group-

chown root:shadow /etc/gshadow- && chmod o-rwx,g-rw /etc/gshadow-


chown root:root /etc/security/pwquality.conf
chmod 600 /etc/security/pwquality.conf

chown root:root /etc/pam.d/common-password
chmod 600 /etc/pam.d/common-password

chown root:root /etc/audit/audit.rules /etc/audit/audit.conf /etc/audit/rules.d/*
chmod -R 640 /etc/audit/audit.rules /etc/audit/audit.conf /etc/audit/rules.d/*

chown root:root /etc/default/grub 
chmod 600 /etc/default/grub

chown root:root /etc/motd && chmod 644 /etc/motd

chown root:root /etc/issue
chmod 644 /etc/issue

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

chown root:root /etc/crontab && chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly && chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily && chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly && chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly && chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d && chmod og-rwx /etc/cron.d

rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

echo "${GREEN}Remediated:${NC} Critical files secured"
echo
echo "${RED}16.1${NC} Setting Sticky bit on all world-writable directories"

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "${GREEN}Remediated:${NC} Sticky bits set"

