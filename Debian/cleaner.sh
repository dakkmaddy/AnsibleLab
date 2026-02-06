#!/bin/bash
 #Removes old revisions of snaps
 #CLOSE ALL SNAPS BEFORE RUNNING THIS
 set -eu
 LANG=en_US.UTF-8 snap list --all | awk '/disabled/{print $1, $3}' |
     while read snapname revision; do
         snap remove "$snapname" --revision="$revision"
     done
journalctl --vacuum-time=7d
apt autoremove
apt clean
apt purge
apt update && apt upgrade -y
apt autoremove -y
#find / -type f -size +100M
exit 1
