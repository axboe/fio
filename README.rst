Overview and history
--------------------

Fio was originally written to save me the hassle of writing special test case
programs when I wanted to test a specific workload, either for performance
reasons or to find/reproduce a bug. The process of writing such a test app can
be tiresome, especially if you have to do it often.  Hence I needed a tool that
would be able to simulate a given I/O workload without resorting to writing a
tailored test case again and again.

A test work load is difficult to define, though. There can be any number of
processes or threads involved, and they can each be using their own way of
generating I/O. You could have someone dirtying large amounts of memory in an
memory mapped file, or maybe several threads issuing reads using asynchronous
I/O. fio needed to be flexible enough to simulate both of these cases, and many
more.

Fio spawns a number of threads or processes doing a particular type of I/O
action as specified by the user. fio takes a number of global parameters, each
inherited by the thread unless otherwise parameters given to them overriding
that setting is given.  The typical use of fio is to write a job file matching
the I/O load one wants to simulate.


Source
------

Fio resides in a git repo, the canonical place is:

	git://git.kernel.dk/fio.git

When inside a corporate firewall, git:// URL sometimes does not work.
If git:// does not work, use the http protocol instead:

	http://git.kernel.dk/fio.git

Snapshots are frequently generated and :file:`fio-git-*.tar.gz` include the git
meta data as well. Other tarballs are archives of official fio releases.
Snapshots can download from:

	http://brick.kernel.dk/snaps/

There are also two official mirrors. Both of these are automatically synced with
the main repository, when changes are pushed. If the main repo is down for some
reason, either one of these is safe to use as a backup:

	git://git.kernel.org/pub/scm/linux/kernel/git/axboe/fio.git

	https://git.kernel.org/pub/scm/linux/kernel/git/axboe/fio.git

or

	git://github.com/axboe/fio.git

	https://github.com/axboe/fio.git


Mailing list
------------

The fio project mailing list is meant for anything related to fio including
general discussion, bug reporting, questions, and development.

An automated mail detailing recent commits is automatically sent to the list at
most daily. The list address is fio@vger.kernel.org, subscribe by sending an
email to majordomo@vger.kernel.org with

	subscribe fio

in the body of the email. Archives can be found here:

	http://www.spinics.net/lists/fio/

and archives for the old list can be found here:

	http://maillist.kernel.dk/fio-devel/


Author
------

Fio was written by Jens Axboe <axboe@kernel.dk> to enable flexible testing of
the Linux I/O subsystem and schedulers. He got tired of writing specific test
applications to simulate a given workload, and found that the existing I/O
benchmark/test tools out there weren't flexible enough to do what he wanted.

Jens Axboe <axboe@kernel.dk> 20060905


Binary packages
---------------

Debian:
	Starting with Debian "Squeeze", fio packages are part of the official
	Debian repository. http://packages.debian.org/search?keywords=fio .

Ubuntu:
	Starting with Ubuntu 10.04 LTS (aka "Lucid Lynx"), fio packages are part
	of the Ubuntu "universe" repository.
	http://packages.ubuntu.com/search?keywords=fio .

Red Hat, Fedora, CentOS & Co:
	Starting with Fedora 9/Extra Packages for Enterprise Linux 4, fio
	packages are part of the Fedora/EPEL repositories.
	https://admin.fedoraproject.org/pkgdb/package/rpms/fio/ .

Mandriva:
	Mandriva has integrated fio into their package repository, so installing
	on that distro should be as easy as typing ``urpmi fio``.

Solaris:
	Packages for Solaris are available from OpenCSW. Install their pkgutil
	tool (http://www.opencsw.org/get-it/pkgutil/) and then install fio via
	``pkgutil -i fio``.

Windows:
	Rebecca Cran <rebecca+fio@bluestop.org> has fio packages for Windows at
	http://www.bluestop.org/fio/ .

BSDs:
	Packages for BSDs may be available from their binary package repositories.
	Look for a package "fio" using their binary package managers.


Building
--------

Just type::

 $ ./configure
 $ make
 $ make install

Note that GNU make is required. On BSDs it's available from devel/gmake within
ports directory; on Solaris it's in the SUNWgmake package.  On platforms where
GNU make isn't the default, type ``gmake`` instead of ``make``.

Configure will print the enabled options. Note that on Linux based platforms,
the libaio development packages must be installed to use the libaio
engine. Depending on distro, it is usually called libaio-devel or libaio-dev.

For gfio, gtk 2.18 (or newer), associated glib threads, and cairo are required
to be installed.  gfio isn't built automatically and can be enabled with a
``--enable-gfio`` option to configure.

To build fio with a cross-compiler::

 $ make clean
 $ make CROSS_COMPILE=/path/to/toolchain/prefix

Configure will attempt to determine the target platform automatically.

It's possible to build fio for ESX as well, use the ``--esx`` switch to
configure.


Windows
~~~~~~~

On Windows, Cygwin (http://www.cygwin.com/) is required in order to build
fio. To create an MSI installer package install WiX 3.8 from
http://wixtoolset.org and run :file:`dobuild.cmd` from the :file:`os/windows`
directory.

How to compile fio on 64-bit Windows:

 1. Install Cygwin (http://www.cygwin.com/). Install **make** and all
    packages starting with **mingw64-i686** and **mingw64-x86_64**.
 2. Open the Cygwin Terminal.
 3. Go to the fio directory (source files).
 4. Run ``make clean && make -j``.

To build fio on 32-bit Windows, run ``./configure --build-32bit-win`` before
``make``.

It's recommended that once built or installed, fio be run in a Command Prompt or
other 'native' console such as console2, since there are known to be display and
signal issues when running it under a Cygwin shell (see
http://code.google.com/p/mintty/issues/detail?id=56 for details).


Documentation
~~~~~~~~~~~~~

Fio uses Sphinx_ to generate documentation from the reStructuredText_ files.
To build HTML formatted documentation run ``make -C doc html`` and direct your
browser to :file:`./doc/output/html/index.html`.  To build manual page run
``make -C doc man`` and then ``man doc/output/man/fio.1``.  To see what other
output formats are supported run ``make -C doc help``.

.. _reStructuredText: http://www.sphinx-doc.org/rest.html
.. _Sphinx: http://www.sphinx-doc.org


Platforms
---------

Fio works on (at least) Linux, Solaris, AIX, HP-UX, OSX, NetBSD, OpenBSD,
Windows, FreeBSD, and DragonFly. Some features and/or options may only be
available on some of the platforms, typically because those features only apply
to that platform (like the solarisaio engine, or the splice engine on Linux).

Some features are not available on FreeBSD/Solaris even if they could be
implemented, I'd be happy to take patches for that. An example of that is disk
utility statistics and (I think) huge page support, support for that does exist
in FreeBSD/Solaris.

Fio uses pthread mutexes for signalling and locking and some platforms do not
support process shared pthread mutexes. As a result, on such platforms only
threads are supported. This could be fixed with sysv ipc locking or other
locking alternatives.

Other \*BSD platforms are untested, but fio should work there almost out of the
box. Since I don't do test runs or even compiles on those platforms, your
mileage may vary. Sending me patches for other platforms is greatly
appreciated. There's a lot of value in having the same test/benchmark tool
available on all platforms.

Note that POSIX aio is not enabled by default on AIX. Messages like these::

    Symbol resolution failed for /usr/lib/libc.a(posix_aio.o) because:
        Symbol _posix_kaio_rdwr (number 2) is not exported from dependent module /unix.

indicate one needs to enable POSIX aio. Run the following commands as root::

    # lsdev -C -l posix_aio0
        posix_aio0 Defined  Posix Asynchronous I/O
    # cfgmgr -l posix_aio0
    # lsdev -C -l posix_aio0
        posix_aio0 Available  Posix Asynchronous I/O

POSIX aio should work now. To make the change permanent::

    # chdev -l posix_aio0 -P -a autoconfig='available'
        posix_aio0 changed


Running fio
-----------

Running fio is normally the easiest part - you just give it the job file
(or job files) as parameters::

	$ fio [options] [jobfile] ...

and it will start doing what the *jobfile* tells it to do. You can give more
than one job file on the command line, fio will serialize the running of those
files. Internally that is the same as using the :option:`stonewall` parameter
described in the parameter section.

If the job file contains only one job, you may as well just give the parameters
on the command line. The command line parameters are identical to the job
parameters, with a few extra that control global parameters.  For example, for
the job file parameter :option:`iodepth=2 <iodepth>`, the mirror command line
option would be :option:`--iodepth 2 <iodepth>` or :option:`--iodepth=2
<iodepth>`. You can also use the command line for giving more than one job
entry. For each :option:`--name <name>` option that fio sees, it will start a
new job with that name.  Command line entries following a
:option:`--name <name>` entry will apply to that job, until there are no more
entries or a new :option:`--name <name>` entry is seen. This is similar to the
job file options, where each option applies to the current job until a new []
job entry is seen.

fio does not need to run as root, except if the files or devices specified in
the job section requires that. Some other options may also be restricted, such
as memory locking, I/O scheduler switching, and decreasing the nice value.

If *jobfile* is specified as ``-``, the job file will be read from standard
input.
