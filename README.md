# getsploits
 Exploit searcher. Downloads exploits archive from exploit-db.com, generates a local database that allows efficient local search of all exploits by many parameters.
 
 Available search parameters:
 * Exploit title/description (as first argument)
 * Type
 * Platform
 * Author
 * Port
 * Text inside exploits

You can combine many search parameters to narrow down the results:
```getsploits.py 0day --type local --platform linux windows```
 
## Usage help screen
```
usage: getsploits.py [-h] [-u] [-s] [--text TEXT]
                     [--type [{webapps,dos,local,shellcode,remote} [{webapps,dos,local,shellcode,remote} ...]]]
                     [--platform [{java,freebsd,php,lin_x86-64,linux,sco_x86,minix,ultrix,solaris,solaris_sparc,lin_amd64,hp-ux,openbsd,sco,solaris_x86,unixware,linux_ppc,irix,perl,netware,cfm,openbsd_x86,freebsd_x86,beos,atheos,ios,mips,hardware,arm,unix,osx,multiple,plan9,windows,bsd,android,freebsd_x86-64,bsd_ppc,aix,win32,immunix,bsdi_x86,tru64,linux_sparc,asp,jsp,osx_ppc,bsd_x86,palm_os,lin_x86,win64,cgi,sh4,netbsd_x86,generator,qnx,novell,linux_mips,xml} [{java,freebsd,php,lin_x86-64,linux,sco_x86,minix,ultrix,solaris,solaris_sparc,lin_amd64,hp-ux,openbsd,sco,solaris_x86,unixware,linux_ppc,irix,perl,netware,cfm,openbsd_x86,freebsd_x86,beos,atheos,ios,mips,hardware,arm,unix,osx,multiple,plan9,windows,bsd,android,freebsd_x86-64,bsd_ppc,aix,win32,immunix,bsdi_x86,tru64,linux_sparc,asp,jsp,osx_ppc,bsd_x86,palm_os,lin_x86,win64,cgi,sh4,netbsd_x86,generator,qnx,novell,linux_mips,xml} ...]]]
                     [--author [E_AUTHOR [E_AUTHOR ...]]]
                     [--port [PORT [PORT ...]]]
                     [description]

optional arguments:
  -h, --help            show this help message and exit
  -u                    Download the latest exploit archive
  -s                    Generate sqlite database

Search options:
  description           Text inside exploit title
  --text TEXT           Exploit content search
  --type [{webapps,dos,local,shellcode,remote} [{webapps,dos,local,shellcode,remote} ...]]
                        Type
  --platform [{java,freebsd,php,lin_x86-64,linux,sco_x86,minix,ultrix,solaris,solaris_sparc,lin_amd64,hp-ux,openbsd,sco,solaris_x86,unixware,linux_ppc,irix,perl,netware,cfm,openbsd_x86,freebsd_x86,beos,atheos,ios,mips,hardware,arm,unix,osx,multiple,plan9,windows,bsd,android,freebsd_x86-64,bsd_ppc,aix,win32,immunix,bsdi_x86,tru64,linux_sparc,asp,jsp,osx_ppc,bsd_x86,palm_os,lin_x86,win64,cgi,sh4,netbsd_x86,generator,qnx,novell,linux_mips,xml} [{java,freebsd,php,lin_x86-64,linux,sco_x86,minix,ultrix,solaris,solaris_sparc,lin_amd64,hp-ux,openbsd,sco,solaris_x86,unixware,linux_ppc,irix,perl,netware,cfm,openbsd_x86,freebsd_x86,beos,atheos,ios,mips,hardware,arm,unix,osx,multiple,plan9,windows,bsd,android,freebsd_x86-64,bsd_ppc,aix,win32,immunix,bsdi_x86,tru64,linux_sparc,asp,jsp,osx_ppc,bsd_x86,palm_os,lin_x86,win64,cgi,sh4,netbsd_x86,generator,qnx,novell,linux_mips,xml} ...]]
                        Platform
  --author [E_AUTHOR [E_AUTHOR ...]]
                        Author
  --port [PORT [PORT ...]]
                        Port number
```
