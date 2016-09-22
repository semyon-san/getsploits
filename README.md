# getsploits
 Exploit searcher. Downloads exploits archive from exploit-db.com, generates a local database that allows efficient local search of all exploits by many parameters.
 
 Available search parameters:
 * Exploit title/description (as first argument)
 * Type
 * Platform
 * Author
 * Port
 * Id
 * Text inside exploits

You can combine many search parameters to narrow down the results:
```
$ getsploits.py 'kernel 3' --type local --platform linux

[ 37292 | 2015-06-16 ]
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Privilege Escalation
exploit-database-master/platforms/linux/local/37292.c

[ 37293 | 2015-06-16 ]
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Privilege Escalation (Access /etc/shadow)
exploit-database-master/platforms/linux/local/37293.txt

[ 35370 | 2014-11-25 ]
Linux Kernel 3.14.5 (RHEL / CentOS 7) - 'libfutex' Privilege Escalation
exploit-database-master/platforms/linux/local/35370.c

[ 33824 | 2014-06-21 ]
Linux Kernel 3.13 - Privilege Escalation PoC (gid)
exploit-database-master/platforms/linux/local/33824.c

[ 33589 | 2014-05-31 ]
Linux Kernel 3.2.0-23 / 3.5.0-23 (Ubuntu 12.04/12.04.1/12.04.2 x64) - 'perf_swevent_init' Privilege Escalation (3)
exploit-database-master/platforms/linux/local/33589.c

[ 39214 | 2014-05-28 ]
Linux Kernel 3.3.5 - '/drivers/media/media-device.c' Local Information Disclosure
exploit-database-master/platforms/linux/local/39214.c

[ 33516 | 2014-05-26 ]
Linux Kernel 3.14-rc1 <= 3.15-rc4 (x64) - Raw Mode PTY Local Echo Race Condition Privilege Escalation
exploit-database-master/platforms/linux/local/33516.c

[ 31346 | 2014-02-02 ]
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.10) - 'CONFIG_X86_X32' Arbitrary Write Exploit (2)
exploit-database-master/platforms/linux/local/31346.c

[ 31347 | 2014-02-02 ]
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10) - 'CONFIG_X86_X32=y' Privilege Escalation (3)
exploit-database-master/platforms/linux/local/31347.c

[ 27297 | 2013-08-02 ]
Linux Kernel 3.7.6 (Redhat x86/x64) - 'MSR' Driver Privilege Escalation
exploit-database-master/platforms/linux/local/27297.c

[ 38559 | 2013-06-07 ]
Linux Kernel 3.3.5 - 'b43' Wireless Driver Privilege Escalation
exploit-database-master/platforms/linux/local/38559.txt

[ 38390 | 2013-03-13 ]
Linux Kernel 3.0 < 3.3.5 - 'CLONE_NEWUSER|CLONE_FS' Privilege Escalation
exploit-database-master/platforms/linux/local/38390.c

[ 33336 | 2013-02-24 ]
Linux Kernel 3.3 < 3.8 (Ubuntu / Fedora 18) - 'sock_diag_handlers()' Privilege Escalation (3)
exploit-database-master/platforms/linux/local/33336.c

[ 37937 | 2012-10-09 ]
Linux Kernel 3.2.x - 'uname()' System Call Local Information Disclosure
exploit-database-master/platforms/linux/local/37937.c

[ 36294 | 2011-11-07 ]
Linux Kernel 3.0.4 - '/proc/interrupts' Password Length Local Information Disclosure
exploit-database-master/platforms/linux/local/36294.c
```
 
## Usage help screen
```
usage: getsploits.py [-h] [-u] [-s] [--text TEXT]
                     [--type [{shellcode,webapps,dos,remote,local} [{shellcode,webapps,dos,remote,local} ...]]]
                     [--platform [{minix,xml,solaris_sparc,bsd_x86,win64,arm,sh4,hp-ux,android,jsp,qnx,windows,ultrix,atheos,hardware,perl,solaris_x86,lin_x86,asp,palm_os,sco,bsdi_x86,aix,cfm,openbsd_x86,freebsd_x86,unix,netware,freebsd_x86-64,linux,plan9,bsd_ppc,beos,ios,multiple,osx_ppc,linux_ppc,irix,lin_x86-64,linux_mips,netbsd_x86,openbsd,bsd,cgi,win32,novell,mips,unixware,sco_x86,osx,lin_amd64,freebsd,immunix,tru64,linux_sparc,solaris,java,generator,php} [{minix,xml,solaris_sparc,bsd_x86,win64,arm,sh4,hp-ux,android,jsp,qnx,windows,ultrix,atheos,hardware,perl,solaris_x86,lin_x86,asp,palm_os,sco,bsdi_x86,aix,cfm,openbsd_x86,freebsd_x86,unix,netware,freebsd_x86-64,linux,plan9,bsd_ppc,beos,ios,multiple,osx_ppc,linux_ppc,irix,lin_x86-64,linux_mips,netbsd_x86,openbsd,bsd,cgi,win32,novell,mips,unixware,sco_x86,osx,lin_amd64,freebsd,immunix,tru64,linux_sparc,solaris,java,generator,php} ...]]]
                     [--author [E_AUTHOR [E_AUTHOR ...]]]
                     [--port [PORT [PORT ...]]] [--id [ID [ID ...]]]
                     [description]

optional arguments:
  -h, --help            show this help message and exit
  -u                    Download the latest exploit archive
  -s                    Generate sqlite database

Search options:
  description           Text inside exploit title
  --text TEXT           Exploit content search
  --type [{shellcode,webapps,dos,remote,local} [{shellcode,webapps,dos,remote,local} ...]]
                        Type
  --platform [{minix,xml,solaris_sparc,bsd_x86,win64,arm,sh4,hp-ux,android,jsp,qnx,windows,ultrix,atheos,hardware,perl,solaris_x86,lin_x86,asp,palm_os,sco,bsdi_x86,aix,cfm,openbsd_x86,freebsd_x86,unix,netware,freebsd_x86-64,linux,plan9,bsd_ppc,beos,ios,multiple,osx_ppc,linux_ppc,irix,lin_x86-64,linux_mips,netbsd_x86,openbsd,bsd,cgi,win32,novell,mips,unixware,sco_x86,osx,lin_amd64,freebsd,immunix,tru64,linux_sparc,solaris,java,generator,php} [{minix,xml,solaris_sparc,bsd_x86,win64,arm,sh4,hp-ux,android,jsp,qnx,windows,ultrix,atheos,hardware,perl,solaris_x86,lin_x86,asp,palm_os,sco,bsdi_x86,aix,cfm,openbsd_x86,freebsd_x86,unix,netware,freebsd_x86-64,linux,plan9,bsd_ppc,beos,ios,multiple,osx_ppc,linux_ppc,irix,lin_x86-64,linux_mips,netbsd_x86,openbsd,bsd,cgi,win32,novell,mips,unixware,sco_x86,osx,lin_amd64,freebsd,immunix,tru64,linux_sparc,solaris,java,generator,php} ...]]
                        Platform
  --author [E_AUTHOR [E_AUTHOR ...]]
                        Author
  --port [PORT [PORT ...]]
                        Port number
  --id [ID [ID ...]]    Exploit ID
```
