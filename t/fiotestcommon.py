#!/usr/bin/env python3
"""
fiotestcommon.py

This contains constant definitions, helpers, and a Requirements class that can
be used to help with running fio tests.
"""

import os
import locale
import logging
import platform
import subprocess
import multiprocessing


SUCCESS_DEFAULT = {
    'zero_return': True,
    'stderr_empty': True,
    'timeout': 600,
    }
SUCCESS_LONG = {
    'zero_return': True,
    'stderr_empty': True,
    'timeout': 3600,
    }
SUCCESS_NONZERO = {
    'zero_return': False,
    'stderr_empty': False,
    'timeout': 600,
    }
SUCCESS_STDERR = {
    'zero_return': True,
    'stderr_empty': False,
    'timeout': 600,
    }


def get_file(filename):
    """Safely read a file."""
    file_data = ''
    success = True

    try:
        with open(filename, "r", encoding=locale.getpreferredencoding()) as output_file:
            file_data = output_file.read()
    except OSError:
        success = False

    return file_data, success


class Requirements():
    """Requirements consists of multiple run environment characteristics.
    These are to determine if a particular test can be run"""

    _linux = False
    _libaio = False
    _io_uring = False
    _zbd = False
    _root = False
    _zoned_nullb = False
    _not_macos = False
    _not_windows = False
    _unittests = False
    _cpucount4 = False
    _nvmecdev = False

    def __init__(self, fio_root, args):
        Requirements._not_macos = platform.system() != "Darwin"
        Requirements._not_windows = platform.system() != "Windows"
        Requirements._linux = platform.system() == "Linux"

        if Requirements._linux:
            config_file = os.path.join(fio_root, "config-host.h")
            contents, success = get_file(config_file)
            if not success:
                print(f"Unable to open {config_file} to check requirements")
                Requirements._zbd = True
            else:
                Requirements._zbd = "CONFIG_HAS_BLKZONED" in contents
                Requirements._libaio = "CONFIG_LIBAIO" in contents

            contents, success = get_file("/proc/kallsyms")
            if not success:
                print("Unable to open '/proc/kallsyms' to probe for io_uring support")
            else:
                Requirements._io_uring = "io_uring_setup" in contents

            Requirements._root = os.geteuid() == 0
            if Requirements._zbd and Requirements._root:
                try:
                    subprocess.run(["modprobe", "null_blk"],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
                    if os.path.exists("/sys/module/null_blk/parameters/zoned"):
                        Requirements._zoned_nullb = True
                except Exception:
                    pass

        if platform.system() == "Windows":
            utest_exe = "unittest.exe"
        else:
            utest_exe = "unittest"
        unittest_path = os.path.join(fio_root, "unittests", utest_exe)
        Requirements._unittests = os.path.exists(unittest_path)

        Requirements._cpucount4 = multiprocessing.cpu_count() >= 4
        Requirements._nvmecdev = args.nvmecdev if hasattr(args, 'nvmecdev') else False

        req_list = [
                Requirements.linux,
                Requirements.libaio,
                Requirements.io_uring,
                Requirements.zbd,
                Requirements.root,
                Requirements.zoned_nullb,
                Requirements.not_macos,
                Requirements.not_windows,
                Requirements.unittests,
                Requirements.cpucount4,
                Requirements.nvmecdev,
                    ]
        for req in req_list:
            value, desc = req()
            logging.debug("Requirements: Requirement '%s' met? %s", desc, value)

    @classmethod
    def linux(cls):
        """Are we running on Linux?"""
        return Requirements._linux, "Linux required"

    @classmethod
    def libaio(cls):
        """Is libaio available?"""
        return Requirements._libaio, "libaio required"

    @classmethod
    def io_uring(cls):
        """Is io_uring available?"""
        return Requirements._io_uring, "io_uring required"

    @classmethod
    def zbd(cls):
        """Is ZBD support available?"""
        return Requirements._zbd, "Zoned block device support required"

    @classmethod
    def root(cls):
        """Are we running as root?"""
        return Requirements._root, "root required"

    @classmethod
    def zoned_nullb(cls):
        """Are zoned null block devices available?"""
        return Requirements._zoned_nullb, "Zoned null block device support required"

    @classmethod
    def not_macos(cls):
        """Are we running on a platform other than macOS?"""
        return Requirements._not_macos, "platform other than macOS required"

    @classmethod
    def not_windows(cls):
        """Are we running on a platform other than Windws?"""
        return Requirements._not_windows, "platform other than Windows required"

    @classmethod
    def unittests(cls):
        """Were unittests built?"""
        return Requirements._unittests, "Unittests support required"

    @classmethod
    def cpucount4(cls):
        """Do we have at least 4 CPUs?"""
        return Requirements._cpucount4, "4+ CPUs required"

    @classmethod
    def nvmecdev(cls):
        """Do we have an NVMe character device to test?"""
        return Requirements._nvmecdev, "NVMe character device test target required"
