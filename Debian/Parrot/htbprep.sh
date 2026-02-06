#!/bin/bash
#
history -c -w
md5sum /etc/shadow | awk -F' ' '{print $1}' > /root/root.txt
ln -sf /dev/null /root/.bash_history
cat /etc/passwd | awk -F':' '{print $1 $2 $3}' | grep 100 | grep -v dhcp | awk -F'x' '{print $1}' > /tmp/passwd.out
head -n 1 /tmp/passwd.out > /tmp/users.txt
for loop in $(cat /tmp/users.txt);
do
	md5sum /etc/passwd | awk -F' ' '{print $1}' > /home/$loop/user.txt
	ln -sf /dev/null /home/$loop/.bash_history
	sudo -u $loop history -w -c
done
rm /tmp/passwd.out
rm /tmp/users.txt
