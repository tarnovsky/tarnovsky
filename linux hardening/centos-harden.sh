#!/bin/bash

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

#yum update -y

###########################################################################################################################

echo
echo -e "${BLUE}1${NC} Initial Setup - Disabling mounts {NC}"
echo
echo -e "${RED}1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e"${GREEN}Remediated:${NC} cramfs disabled"
echo
echo -e "${RED}1.2${NC} Ensure mounting of jffs filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} jffs disabled"
echo
echo -e "${RED}1.3${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} hfs disabled"
echo
echo -e "${RED}1.4${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} hfsplus disabled"
echo
echo -e "${RED}1.5${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} udf disabled"
echo
echo -e "${RED}1.6${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} freevxfs disabled"
echo
echo -e "${RED}1.7${NC} Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} jffs2 disabled"
echo
echo -e "${RED}1.8${NC} Ensure mounting of squashfs filesystems is disabled"
modprobe -n -v squashfs | grep "^install /bin/true$" || echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} squashfs disabled"
echo
echo -e "${RED}1.9${NC} Ensure mounting of FAT filesystems is disabled"
modprobe -n -v vfat | grep "^install /bin/true$" || echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} FAT disabled"
echo
echo -e "${RED}1.6${NC} Disable Automounting"
systemctl disable autofs.service
echo -e "${GREEN}Remediated:${NC} automounting disabled"

############################################################################################## 

echo
echo -e "${BLUE}2 Initial Setup - Filesystem Integrity Checking${NC}"

#Ensure AIDE is installed
echo
echo -e "${RED}2.1${NC} Ensure AIDE is installed"
yum -y install aide && aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

#Ensure filesystem integrity is regularly checked
echo
echo -e "${RED}2.2${NC} Ensure filesystem integrity is regularly checked"
(crontab -u root -l; crontab -u root -l | egrep -q "^0 5 \* \* \* /usr/sbin/aide --check$" || echo "0 5 * * * /usr/sbin/aide --check" ) | crontab -u root -

echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"

############################################################################################################################

##Category 1.4 Initial Setup - Secure Boot Settings
echo
echo -e "${BLUE}1.4 Initial Setup - Secure Boot Settings${NC}"
 
#Ensure permissions on bootloader config are configured
echo
echo -e "${RED}1.4.1${NC} Ensure permissions on bootloader config are configured"
chown root:root /boot/grub2/grub.cfg && chmod og-rwx /boot/grub2/grub.cfg && chown root:root /boot/grub2/user.cfg && chmod og-rwx /boot/grub2/user.cfg

echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"


#Ensure authentication required for single user mode
echo
echo -e "${RED}1.4.3${NC} Ensure authentication required for single user mode"
egrep -q "^\s*ExecStart" /usr/lib/systemd/system/rescue.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/rescue.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/rescue.service
egrep -q "^\s*ExecStart" /usr/lib/systemd/system/emergency.service && sed -ri "s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/" /usr/lib/systemd/system/emergency.service || echo "ExecStart=-/bin/sh -c \"/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /usr/lib/systemd/system/emergency.service
echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"

############################################################################################################################

##Category 1.5 Initial Setup - Additional Process Hardening
echo
echo -e "${BLUE}1.5 Initial Setup - Additional Process Hardening${NC}"

#Ensure core dumps are restricted
echo
echo -e "${RED}1.5.1${NC} Ensure core dumps are restricted"
egrep -q "^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$" /etc/security/limits.conf && sed -ri "s/^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$/\1* hard core 0\2/" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf
egrep -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$/\1fs.suid_dumpable = 0\2/" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure core dumps are restricted"
 
#Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"

############################################################################################################################

##Category 3.1 Network Configuration - Network Parameters (Host Only)
echo
echo -e "${BLUE}3.1 Network Configuration - Network Parameters (Host Only)${NC}"
 
#Ensure IP forwarding is disabled
echo
echo -e "${RED}3.1.1${NC} Ensure IP forwarding is disabled"
egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"


#Ensure packet redirect sending is disabled
echo
echo -e "${RED}3.1.2${NC} Ensure packet redirect sending is disabled"
egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"

############################################################################################################################

##Category 3.6 Network Configuration - Firewall Configuration
echo
echo -e "${BLUE}3.6 Network Configuration - Firewall Configuration${NC}"
sh templates/iptables.sh
cp templates/iptables.sh /etc/init.d/
chmod +x /etc/init.d/iptables.sh
ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
echo  "${GREEN}Remediated:${NC} IPTABLE script ran. Refer to README"

############################################################################################## 

echo
echo -e "${BLUE}12${NC} Initial Setup - Configuring audit.rules${NC}"
yum -y install auditd 
systemctl enable auditd.service
cp templates/stig.rules /etc/audit/rules.d/stig.rules
cp templates/audit.rules /etc/audit/audit.rules
cp templates/auditd.conf /etc/audit/auditd.conf 
systemctl restart auditd
augenrules --load
echo -e "${GREEN}Remediated:${NC} audit.rules set"

############################################################################################## 

##Category 4.2 Logging and Auditing - Configure rsyslog
echo
echo -e "${BLUE}4.2 Logging and Auditing - Configure rsyslog${NC}"
 
#Ensure rsyslog Service is enabled
echo
echo -e "${RED}4.2.1.1${NC} Ensure rsyslog Service is enabled"
systemctl enable rsyslog
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"

 
#Ensure rsyslog default file permissions configured
echo
echo -e "${RED}4.2.1.3${NC} Ensure rsyslog default file permissions configured"
grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"
 
#Ensure remote rsyslog messages are only accepted on designated log hosts
echo
echo -e "${RED}4.2.1.5${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
sed -i -e 's/#$ModLoad imtcp/$ModLoad imtcp/g' /etc/rsyslog.conf
grep "$ModLoad imtcp" /etc/rsyslog.conf || echo "$""ModLoad imtcp" >> /etc/rsyslog.conf
sed -i -e 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
grep "$InputTCPServerRun 514" /etc/rsyslog.conf || echo "$""InputTCPServerRun 514" >> /etc/rsyslog.conf
pkill -HUP rsyslogd
echo -e "${GREEN}Remediated:${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
 
#Ensure syslog-ng service is enabled
echo
echo -e "${RED}4.2.2.1${NC} Ensure syslog-ng service is enabled"
yum -y install syslog-ng && systemctl enable syslog-ng
echo -e "${GREEN}Remediated:${NC} Ensure syslog-ng service is enabled"

#Ensure rsyslog or syslog-ng is installed
echo
echo -e "${RED}4.2.3${NC} Ensure rsyslog or syslog-ng is installed"
yum -y install rsyslog && yum -y install syslog-ng
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog or syslog-ng is installed"

#Ensure permissions on all logfiles are configured
echo
echo -e "${RED}4.2.4${NC} Ensure permissions on all logfiles are configured"
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"

############################################################################################## 

echo
echo -e "${RED}9.5${NC} Secure Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
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
echo -e "${GREEN}Remediated:${NC} Cron Secured"
echo

############################################################################################################################

##Category 5.2 Access, Authentication and Authorization - SSH Server Configuration
echo
echo -e "${BLUE}5.2 Access, Authentication and Authorization - SSH Server Configuration${NC}"

cp templates/sshd_config /etc/ssh/ssh_config; echo "OK"
cp templates/sshd_config /etc/ssh/sshd_config; echo "OK"
systemctl restart sshd

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
echo  "${GREEN}Remediated:${NC} SSH secured"

##############################################################################################

echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"
echo
echo  "${RED}9.11${NC} Adding time display of last login to system"
echo "session required pam_lastlog.so showfailed" >> /etc/pam.d/login
echo  "${GREEN}Remediated:${NC} Time displayed"
echo
echo  "${RED}9.12${NC} Increasing password complexity requirements${NC}"
yum -y install libpam-pwquality
cp templates/pwquality.conf /etc/security/pwquality.conf
cp templates/common-password /etc/pam.d/common-password
echo  "${GREEN}Remediated:${NC} Password complexity set"
echo
echo  "${RED}9.13${NC} Configuring faillock {NC}"
cp templates/common-auth /etc/pam.d/common-auth
cp templates/faillock.conf /etc/security/faillock.conf
echo  "${GREEN}Remediated:${NC} faillock configured"
chown root:root /etc/security/pwquality.conf
chmod 600 /etc/security/pwquality.conf

chown root:root /etc/pam.d/common-password
chmod 600 /etc/pam.d/common-password

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"
echo
echo   "${RED}5.4.1${NC} Ensure inactive password lock is 30 days or less"
cp templates/login.defs /etc/login.defs
echo  "${GREEN}Remediated:${NC} UMASK set to Restrictive Value (027)"

#Ensure inactive password lock is 30 days or less
echo
echo -e "${RED}5.4.2${NC} Ensure inactive password lock is 30 days or less"
useradd -D -f 30
echo  "${GREEN}Remediated:${NC} account settings updated"

#Ensure system accounts are non-login
echo
echo -e "${RED}5.4.3${NC} Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    /usr/sbin/usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
      /usr/sbin/usermod -s /sbin/nologin $user
    fi
  fi
done
echo -e "${GREEN}Remediated:${NC} Ensure system accounts are non-login"

#Ensure default group for the root account is GID 0
echo
echo -e "${RED}5.4.4${NC} Ensure default group for the root account is GID 0"
usermod -g 0 root
echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"

#Ensure default user umask is 027 or more restrictive
echo
echo -e "${RED}5.4.5${NC} Ensure default user umask is 027 or more restrictive"
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/bashrc || echo "umask 077" >> /etc/bashrc
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile || echo "umask 077" >> /etc/profile
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile.d/*.sh || echo "umask 077" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"

#Ensure default user shell timeout is 900 seconds or less
echo
echo -e "${RED}5.4.6${NC} Ensure default user shell timeout is 900 seconds or less"
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/bashrc || echo "TMOUT=600" >> /etc/bashrc
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile || echo "TMOUT=600" >> /etc/profile
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile.d/*.sh || echo "TMOUT=600" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user shell timeout is 900 seconds or less"

#Ensure access to the su command is restricted
echo
echo -e "${RED}5.6${NC} Ensure access to the su command is restricted"
egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
  echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"
 
chmod -R g-wx,o-rwx /var/log/*

chown root:root /etc/ssh/sshd_config
chmod 700 /etc/ssh/sshd_config

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:shadow /etc/shadow
chmod 640 /etc/shadow

chown root:root /etc/group
chmod 644 /etc/group

chown root:shadow /etc/gshadow
chmod 640 /etc/gshadow

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:root /etc/group
chmod 644 /etc/group


chown root:root /etc/passwd-
chmod 130 /etc/passwd-

chown root:shadow /etc/shadow-
chmod 640 /etc/shadow-

chown root:root /etc/group-
chmod 130 /etc/group-

chown root:shadow /etc/gshadow- 
chmod 640 /etc/gshadow-

chown root:root /etc/security/pwquality.conf
chmod 600 /etc/security/pwquality.conf

chown root:root /etc/pam.d/common-password
chmod 644 /etc/pam.d/common-password

chown root:root /etc/audit/audit.rules /etc/audit/audit.conf /etc/audit/rules.d/*
chmod -R 640 /etc/audit/audit.rules /etc/audit/audit.conf /etc/audit/rules.d/*

chown root:root /etc/default/grub 
chmod 600 /etc/default/grub

chown root:root /etc/motd && chmod 644 /etc/motd

chown root:root /etc/issue
chmod 644 /etc/issue

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

echo "${GREEN}Remediated:${NC} Critical files secured"

##############################################################################################

echo
echo -e "${BLUE}7${NC} Initial Setup - Creating Admin User${NC}"
username="milton"
useradd -m $username
echo "$username:zrX@Ez?piHSz1g~R$!Zk]e2c" | chpasswd
echo "$username ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
if [ ! -d '/home/$username/.ssh/' ]
then
    mkdir /home/$username/.ssh
    chown $username:$username /home/$username/.ssh
    chmod 700 /home/$username/.ssh
fi
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCao5gbrOSBHaT+a5GC6vEFb5sZJb73bDf8wC7NkR4HB4Iwh3oOLufbTEVy4egIw2hBEuKJqD2FJ+b66OeF306OhUDl9EvYnTl0cJ2jz6Hj0bcJz/v0eH1iJC6F6xVU19dvibvcp8gOBa9hFhGadNHwHdXbd7XNDTQiZrwbhC3v2RFaGQoy7ODJA9u7LKh+8tAiTj2Ma9Ub0fSED6/YQP0XLZO/i1OL8CuYYutw8P5Zdv+lWmgZVr27Id8QoWbFSIVkoHqvmUTqOlGgl6MVgu+3rB0NqSKH4W6mj8HbthS7iC6EWGLXZAx0gR9JOHhxHQhBQl/1PlmNTaZNm0IKUCgvavExpxOBXxdcokAeR/tXmj0zjK7YIaOrl7wiBPSSwr+QVWumS9BQ9dV2vhw3LUkL8j0z0pP2NSbLssyxvo8JyVuEYevh4KLFA2kbMKrFn3Za01jVw+MFEWOp3tW9J10ycdoGbs2UTZkQZOmMwSz5/zwToLzN/ZWAkGvhuD5TS0= milton@ls23" >> /home/$username/.ssh/authorized_keys
chown $username:$username /home/$username/.ssh/authorized_keys
chmod 600 /home/$username/.ssh/authorized_keys
echo -e "${GREEN}Remediated:${NC} User created. Copy private key in Git to your system in order to login in as user"
