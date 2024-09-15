# Linux

## Tools

fallocate -l $[ 1024 * 1024 * 100 ] ./test-3.img

fallocate -n -l 100M testowy

dd if=/dev/zero of=./test-2.img bs=1024 count=$[ 1024 * 100 ]

linux /vmlinuz-310.0.x86_64 root=/dev/sda2 ro quiet init=/bin/sh

mount -o rw,remount /

mount -o ro,remount /

mount --bind /usr/lib ./lib

findmnt

ldd /usr/bin/ls

file /usr/bin/ls

python

f =open("./test.img","r+b")

f.seek((1610 * 4096) + 76)

new_bytes = b'\x31'

f.write(new_bytes)

f.close()

find ./ -inum 12 | xargs rm

sudo apt install sleuthkit

blkcat

blkcat test.img 2457

blkcat -hv test.img 2457

lsblk

blkid

fdisk -l

cfdisk

gdisk

cgdisk

parted

gparted

swapon -s

e2label /dev/sda3

dumpe2fs /dev/sda3

xfs_admin -l /dev/sda1

xfs_admin -u /dev/sda1

xfs_info /dev/sda1

cat /proc/partitions 

df -h

du -ha

mkfs.ext4 

mkswap

swaplabel

fsck.ext4

fsck.xfs

dumpe2fs

tune2fs

debugfs

xfs_repair

xfs_fsr

xfs_db

sudo apt install quota

/etc/fstab - userquota , grpquota

quotacheck -cug <kat>

quotaon -v katalog

quotaoff -v katalog

edquota nazwauser

edquota -g nazwagrupy

repquota kat

sudo apt install smartmontools

sudo smartctl -a /dev/sda

sudo smartctl -s on /dev/sda

sudo badblocks /dev/sda

which cat

type -a cat 

sudo apt install plocate

plocate

readelf -d /usr/bin/cat

readelf -l /usr/bin/cat

objdump -h /usr/bin/cat

objdump -R /usr/bin/cat

ldd /usr/bin/cat

readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep memset

## Sparse files

dd if=/dev/zero of=./test.img bs=1 count=0 seek=100M

mkfs.ext2 ./test.img

ls -lah 

du -ha test.img

mkdir mnt

sudo mount -o loop ./test.img ./mnt

sudo umount ./mnt

echo data on file > plik.txt

sync

debugfs test.img

ls -l

stat <12>

stat somefile.bin

stats

filefrag -v plik.txt

offset = block number * block size

offset = 24576 * 4096

offset = 100663296

dd if=test.img of=extract_data.txt bs=1 count=20 skip=102760448

shred -n 10 file


## Audit files

sudo apt-get install auditd audispd-plugins

echo "test 123" > plik.txt

sudo auditctl -w plik.txt -p rwxa -k log-plik

cat plik.txt

sudo ausearch -k log-plik

strace -e trace=openat cat plik.txt 2>&1 | grep plik.txt

## Linux Security Modules
  - SELINUX
  - AppArmor

sestatus

ls -Z /bin/cat


## Whiteout Files

mkdir lower upper work mnt

echo I reside in the lower dir. > lower/lower-dir-file.txt

echo I reside in the upper dir. > upper/upper-dir-file.txt

sudo mount -t overlay overlay -o lowerdir=lower,upperdir=/upper,workdir=work mnt

ls -la mnt/


## Communications 
 - shared memory (/dev/shm)
 - named pipes
 - sockets
 - tcp/ip ports

exec 3<> /dev/tcp/example.org/80

echo -ne "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n" >&3

cat <&3

exec 3<&-

exec 3>&-

ls -lah /proc/self/fd

nc 10.1.3.16 8000

nc -l 8000

socat tcp-l:5000,reuseaddr,fork EXEC:"/usr/bin/cat /home/noroot/hardfile1",pty,stderr

nc localhost 5000

nc -l 7777 | pv | dd of=/dev/sda bs=1M

dd if=/dev/sda bs=1M | pv | nc 129... 7777

ssh noroot@123.123.123 -L8000:192.168.0.11:80

ssh noroot@123.123.123.123 -R 3333:192.168.1.12:80

mkfifo name

mknode name type main_number minor_number

## Access rights

chmod 0644 file

umask 

capsh --print

getcap /bin/ping

chmod 600 /tmp/asdf

sudo -u good cat /tmp/asdf

getfacl /tmp/asdf  

Setfacl -m u:good:r /tmp/asdf

sudo -u good cat /tmp/asdf

ls -al /tmp/asdf

ls -lad `find / -type d ! -user $(whoami) -writable 2> /dev/null`

find / \( -path /proc -o -path /sys \) -prune -o -type f ! -user $(whoami) -writable 2>/dev/null 

find / \( -perm /4000 -o -type f -exec getcap {} + \) 2> /dev/nul


## Links
https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/#x86_64-64-bit

https://gynvael.coldwind.pl/n/cmds

https://book.hacktricks.xyz/v/pl/generic-methodologies-and-resources/pentesting-network

https://ir0nstone.gitbook.io/notes/binexp/stack/exploiting-over-sockets/socat

http://pwnwiki.io/#!persistence/multi/socat.md




# Windows

## Tools

diskpart

create vdisk file="c:\users\user\files\mnt\img.vhd" maximum=100 type=expandable

attach vdisk

list disk

select disk 

list disk

create partition primary

list part

format fs=ntfs quick

list vol

select vol 2

assign mount="c:\path\directory"

exit

mountvol c:\c:\path\directory /d

auditpol /set /subcategory:"File System" /success:enable /failure:enable

PS> $path = ".\plik.txt"

PS> $acl = Get-Acl $path

PS> $auditRule = New-Object

System.Security.AccessControl.FileSystemAuditRule("Everyone","FullControl", "Success,Failure")

PS> $acl.SetAuditRule($auditRule)

PS> Set-Acl $path $acl

type plik.txt

wevtutil qe /f:Text /rd:true /c:1 Security

echo main stream > file.txt

echo alternative stream 1 > file.txt:alt1

echo alternatywny stream 2 > file.txt:alt2

type file.txt

more < file.txt:alt1

more < file.txt:alt2

more < file.txt::$DATA

dir /r

fsutil file queryEA c:\windows\system32\kernel32.dll

fsutil file queryEA c:\windows\system32\kernel32.dll

compact /c plik.txt

cipher /e plik.txt

cacls

icacls

attrib +h hidden-file

Get-ChildItem -Hidden

## Links 
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files

https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes

https://superuser.com/questions/396692/what-are-these-extended-attributes-eas-in-the-files-in-windows-8/1736010#1736010

https://pauljerimy.com/security-certification-roadmap/

https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.htm

https://blog.orange.tw/posts/2024-08-confusion-attacks-en/

https://project-zero.issues.chromium.org/issues/42451592

https://project-zero.issues.chromium.org/issues/42451596


