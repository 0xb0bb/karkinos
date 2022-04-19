Karkinos
==========

A large library database to assist in binary exploitation on Linux. This tool
can help identify unknown libraries by providing the location of known symbols,
it can help locate the name of packages that contain a given library and it can
find the debugging version of a library you are working with.

Once the library is identified you can dump useful information such as symbols
(both exported symbols and special useful calculated locations that are useful
for exploitation), gadgets for ROP chains or one shot (AKA magic gadgets or one
gadgets) and their constraints.

The usage is inspired by the excellent [libc-database](https://github.com/niklasb/libc-database).

It supports many architectures including:

* x86   (i386  / amd64)
* arm   (arm   / arm64)
* mips  (mips  / mips64)
* ppc   (ppc   / ppc64)
* sparc (sparc / sparc64)
* sh4
* hppa
* m68k
* riscv

There are many libraries indexed over many distributions spanning many years. The
libraries indexed are:

* glibc
* libstdc++
* glibc-ld
* libgcc
* musl

Install
-------

The preferred method is to just download and extract the latest release. Karkinos
will manage updates by itself from that point on. Alternatively, you can clone this repository.

Once you have Karkinos through either method, you can then access the tool by running:

	$ ./kark.py --help

On the first run it will attempt to extract the databases from the compressed files,
you will need to have the `xz` and `cat` binaries installed and availible through the `PATH` env
var.

Usage
-----

	usage: kark.py [-h] [--libdb {glibc,libstdc++}] [--distro DISTRO]
	               [--arch {x86,amd64,i386,arm,arm64,mips,mips64,ppc,ppc64,sparc,sparc64,m68k,hppa,sh4}]
	               [--endian {little,big}]
	               {find,dump,info,update} ...

	description:
	  karkinos is a library database to assist with exploitation by helping to
	  identify libraries from known offsets or to dump useful offsets from those
	  identified libraries. Each database indexes symbols, gadgets and where
	  possible one shot gadgets (AKA magic gadgets or one gadgets).

	architectures indexed:
	  - x86   (amd64, i386)
	  - arm   (arm,   arm64)
	  - mips  (mips,  mips64)
	  - ppc   (ppc,   ppc64)
	  - sparc (sparc, sparc64)
	  - m68k
	  - hppa
	  - sh4
	  - riscv

	libraries indexed:
	  - glibc
	  - libstdc++
	  - glibc-ld
	  - libgcc
	  - musl

	commands:
	  - find        find a library by symbol offsets, file, build id or file hash
	  - dump        dump symbols/gadgets for a given library
	  - info        print some information about a specific library
	  - update      check for updates to the database
	  - version     display version information and exit

	positional arguments:
	  {find,dump,info,update}
	                        command to execute
	  args                  arguments for specific command, see examples

	optional arguments:
	  -h, --help            show this help message and exit
	  --libdb {glibc,libstdc++}
	                        the library database to use
	  --distro DISTRO       the linux distribution to filter in symbol search
	  --arch {x86,amd64,i386,arm,arm64,mips,mips64,ppc,ppc64,sparc,sparc64,m68k,hppa,sh4}
	                        architecture to filter in symbol search
	  --endian {little,big}
	                        endianess to filter in symbol search

	examples:
	  ./kark.py find fgets b20 puts 9c0 fwrite 8a0
	  ./kark.py find 50390b2ae8aaa73c47745040f54e602f
	  ./kark.py find b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0
	  ./kark.py find /lib/x86_64-linux-gnu/libc.so.6
	  ./kark.py --arch arm --endian big find system 440
	  ./kark.py --distro ubuntu fgets b20 puts 9c0
	  ./kark.py dump centos_glibc-2.12-1.107.el6_4.2.x86_64
	  ./kark.py dump opensuse_glibc-2.19-16.9.1.i686 fgets system str_bin_sh
	  ./kark.py info ubuntu_libc6-udeb_2.27-3ubuntu1_amd64
	  ./kark.py update

Screenshots
-----------

![Karkinos](https://github.com/0xb0bb/karkinos/blob/master/docs/images/karkinos.png?raw=true)

TODO
----

* Make the database faster (queries are far from optimised)
* Make the database smaller (schema is not optimal)
* Clean the code up (was hobbled together very quickly)
* More gadgets, more one shot gadgets
* Make usable as a library (remove output, reorganise code)

Contact
-------

[@0xb0bb](https://twitter.com/0xb0bb)
