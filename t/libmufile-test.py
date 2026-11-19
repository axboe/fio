#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-independent regression tests for the libmufile integration."""

import configparser
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BUILD = Path(os.environ.get("FIO_BIN", ROOT / "fio")).resolve().parent


class LibmufileTests(unittest.TestCase):
    def test_smoke_relative_directory(self):
        """Smoke plumbing is testable without advertising real GPU support."""
        with tempfile.TemporaryDirectory(prefix="fio-mufile-smoke-") as tmp:
            path = Path(tmp)
            storage = path / "storage"
            storage.mkdir()
            log = path / "calls"
            fio = path / "fake-fio"
            fio.write_text("""#!/bin/sh
if test "$1" = "--enghelp=libmufile"; then exit 0; fi
case "$FIO_DIR" in /*) ;; *) exit 10 ;; esac
test -d "$FIO_DIR" || exit 11
test "$PWD" = "$FIO_DIR" || exit 12
printf '%s\\n' "$*" >>"$FIO_SMOKE_LOG"
touch "$FIO_DIR/test-artifact"
""", encoding="ascii")
            fio.chmod(0o755)
            env = os.environ.copy()
            env.update(FIO_BIN=str(fio), FIO_DIR="storage", GPU_DEV_IDS="0",
                       FIO_SMOKE_LOG=str(log))
            subprocess.run(["sh", str(ROOT / "t/libmufile-smoke.sh")],
                           cwd=path, env=env, check=True)
            calls = log.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(calls), 7)
            self.assertIn("--section=randverify", calls[-1])
            self.assertEqual(list(storage.iterdir()), [])

    def read_job(self, name):
        config = configparser.ConfigParser(
            allow_no_value=True, interpolation=None)
        config.read(ROOT / "examples" / name)
        return config

    def test_posix_verify(self):
        config = self.read_job("libmufile-posix.fio")
        self.assertEqual(config["global"]["musa_io"], "posix")
        self.assertEqual(config["verify"]["rw"], "write")
        self.assertEqual(config["verify"]["verify"], "md5")

    def test_random_verify(self):
        config = self.read_job("libmufile-mufile.fio")
        self.assertEqual(config["randverify"]["rw"], "randwrite")
        self.assertEqual(config["randverify"]["verify"], "md5")
        # Use more than one block so random offsets are actually exercised.
        self.assertNotEqual(config["global"]["bs"], config["randverify"]["size"])

    def test_jobfiles_parse_and_verify_on_cpu(self):
        """Use sync only to check fio job semantics, not GPU data movement."""
        fio = Path(os.environ.get("FIO_BIN", ROOT / "fio"))
        if not fio.is_file():
            self.skipTest("build fio first")
        with tempfile.TemporaryDirectory(prefix="fio-mufile-jobs-") as tmp:
            env = dict(os.environ, FIO_DIR=tmp, GPU_DEV_IDS="0")
            for name, section in (
                ("libmufile-posix.fio", "verify"),
                ("libmufile-mufile.fio", "randverify"),
            ):
                with self.subTest(job=name):
                    # Remove engine-private options; keep workload options intact.
                    config = self.read_job(name)
                    config["global"]["ioengine"] = "sync"
                    del config["global"]["gpu_dev_ids"]
                    del config["global"]["musa_io"]
                    config["global"]["numjobs"] = "1"
                    config["global"]["direct"] = "0"
                    config["global"]["size"] = "16m"
                    job = Path(tmp) / name
                    with job.open("w", encoding="ascii") as stream:
                        config.write(stream, space_around_delimiters=False)
                    result = subprocess.run([
                        str(fio), "--section=" + section,
                        "--verify_state_save=0", "--unlink=1", str(job),
                    ], env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0,
                                     result.stdout + result.stderr)

class LibmufileConfigureTests(unittest.TestCase):
    """Exercise the real probe block with isolated SDK and pkg-config fixtures."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fio-mufile-config-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.sdk = self.path / "sdk"
        include = self.sdk / "include"
        (include / "mufile").mkdir(parents=True)
        (self.sdk / "lib").mkdir()
        self.header = include / "mufile" / "mufile_c.h"
        self.header.write_text("""
#include <stddef.h>
#include <sys/types.h>
typedef struct { int err; } MUfileError_t;
#define MU_FILE_SUCCESS 0
#define MU_FILE_DRIVER_NOT_INITIALIZED 1
#define MU_FILE_MAX_ERROR 34
#define MU_FILE_HANDLE_TYPE_OPAQUE_FD 1
typedef void *MUFileHandle_t;
typedef struct { int type; union { int fd; } handle; } MUFileDescr_t;
MUfileError_t muFileDriverOpen(void);
void muFileDriverClose(void);
MUfileError_t muFileHandleRegister(MUFileHandle_t *, MUFileDescr_t *);
void muFileHandleDeregister(MUFileHandle_t);
MUfileError_t muFileBufRegister(void *, size_t, int);
void muFileBufDeregister(void *);
const char *muFileGetErrorStringC(MUfileError_t st);
void muFileGetAbiVersion(unsigned *a, unsigned *b, unsigned *c);
ssize_t muFileRead(void *h, void *b, size_t s, off_t f, off_t m);
ssize_t muFileWrite(void *h, void *b, size_t s, off_t f, off_t m);
""", encoding="ascii")
        (include / "musa_runtime.h").write_text("""
#include <stddef.h>
typedef int musaError_t;
#define musaSuccess 0
enum musaMemcpyKind { musaMemcpyHostToDevice = 1, musaMemcpyDeviceToHost = 2 };
const char *musaGetErrorName(musaError_t);
int musaSetDevice(int);
int musaMalloc(void **p, unsigned long s);
int musaFree(void *);
int musaMemset(void *, int, size_t);
int musaMemcpy(void *, const void *, size_t, int);
int musaStreamSynchronize(void *);
""", encoding="ascii")
        self.mufile_source = self.path / "mufile.c"
        self.mufile_source.write_text("""
#include <stddef.h>
#include <sys/types.h>
#include "mufile/mufile_c.h"
const char *muFileGetErrorStringC(MUfileError_t st) { return "test"; }
void muFileGetAbiVersion(unsigned *a, unsigned *b, unsigned *c)
{ *a = 1; *b = 1; *c = 0; }
ssize_t muFileRead(void *h, void *b, size_t s, off_t f, off_t m)
{ return 0; }
ssize_t muFileWrite(void *h, void *b, size_t s, off_t f, off_t m)
{ return 0; }
""", encoding="ascii")
        self.musart_source = self.path / "musart.c"
        self.musart_source.write_text("""
int musaMalloc(void **p, unsigned long s) { return 0; }
""", encoding="ascii")
        self.build_libraries()
        self.pc = self.path / "pkgconfig"
        self.pc.mkdir()
        text = (ROOT / "configure").read_text(encoding="utf-8")
        start = text.index("# libmufile probe")
        end = text.index('print_config "libmufile" "$libmufile"', start)
        self.probe = text[start:end]

    def build_libraries(self, include_write=True):
        cc = shlex.split(os.environ.get("CC", "cc"))
        for source, name in (
                (self.mufile_source, "mufile"),
                (self.musart_source, "musart")):
            source_text = source.read_text(encoding="ascii")
            if name == "mufile" and not include_write:
                source_text = source_text[:source_text.index(
                    "ssize_t muFileWrite")]
            source_to_compile = self.path / f"{name}-fixture.c"
            source_to_compile.write_text(source_text, encoding="ascii")
            obj = self.path / f"{name}-fixture.o"
            subprocess.run(cc + ["-I", str(self.sdk / "include"), "-c",
                                  str(source_to_compile), "-o", str(obj)],
                           check=True)
            subprocess.run(["ar", "rcs", str(self.sdk / "lib" / f"lib{name}.a"),
                            str(obj)], check=True, capture_output=True)

    def metadata(self, version):
        (self.pc / "libmufile.pc").write_text(f"""
prefix={self.sdk}
Name: libmufile
Description: Test-only libmufile C ABI fixture
Version: {version}
Cflags: -I${{prefix}}/include
Libs: -L${{prefix}}/lib -lmufile -lmusart
""", encoding="ascii")

    def run_probe(self, use_sdk=True):
        script = """
set -eu
libmufile=yes
CFLAGS=
LIBS=
TMPC=probe.c
print_config() { :; }
feature_not_found() { echo "missing $*" >&2; exit 1; }
check_min_lib_version() { pkg-config --atleast-version="$2" "$1"; }
compile_prog() { $CC -Werror=implicit-function-declaration $1 "$TMPC" $2 -o probe; }
""" + self.probe
        env = dict(os.environ, CC=os.environ.get("CC", "cc"),
                   MUSA_HOME=str(self.sdk if use_sdk else self.path / "missing"),
                   PKG_CONFIG_PATH=str(self.pc), PKG_CONFIG_LIBDIR=str(self.pc))
        return subprocess.run(["sh", "-c", script], cwd=self.path, env=env,
                              capture_output=True, text=True)

    def test_missing_metadata_rejected_with_sdk_prefix(self):
        result = self.run_probe()
        self.assertNotEqual(result.returncode, 0,
                            "MUSA_HOME must not bypass required pkg-config metadata")
        self.assertIn("pkg-config", result.stderr)

    def test_old_package_version_rejected(self):
        if not shutil.which("pkg-config"):
            self.skipTest("pkg-config not installed")
        self.metadata("1.0.0")
        result = self.run_probe()
        self.assertNotEqual(result.returncode, 0,
                            "old metadata must not fall back to MUSA_HOME")

    def test_pkg_config_supplies_nonstandard_prefix(self):
        if not shutil.which("pkg-config"):
            self.skipTest("pkg-config not installed")
        self.metadata("1.1.0")
        result = self.run_probe(use_sdk=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_write_symbol_rejected(self):
        if not shutil.which("pkg-config"):
            self.skipTest("pkg-config not installed")
        self.metadata("1.1.0")
        self.build_libraries(include_write=False)
        try:
            result = self.run_probe()
        finally:
            self.build_libraries()
        self.assertNotEqual(result.returncode, 0,
                            "probe must require both synchronous entry points")

    def test_engine_registration_span(self):
        source = self.path / "registration-test.c"
        source.write_text("""
#include <assert.h>
#include "fio.h"
#undef fio_init
#undef fio_exit
#define fio_init static
#define fio_exit static
#include "engines/libmufile.c"
static size_t registered_size;
const char *muFileGetErrorStringC(MUfileError_t status) { return "test"; }
ssize_t log_err(const char *format, ...) { return 0; }
MUfileError_t muFileBufRegister(void *p, size_t size, int flags)
{
    MUfileError_t status = { 0 };
    registered_size = size;
    return status;
}
int main(void)
{
    struct thread_data td = { 0 };
    const size_t span = 16 * 1024 * 1024;
    size_t size;

    td.o.iodepth = 16;
    td.o.max_bs[DDIR_READ] = 1024 * 1024;
    td.o.max_bs[DDIR_WRITE] = 1024 * 1024;
    td.orig_buffer_size = span + 4095;
    td.o.odirect = 1;
    size = libmufile_backend.buf_register_size(&td, span + 4095);
    assert(size == span);
    assert(libmufile_buf_register(NULL, size) == 0);
    assert(registered_size == span);
    td.o.iodepth = 1;
    td.o.max_bs[DDIR_WRITE] = span + 1;
    td.orig_buffer_size = span + 4096;
    size = libmufile_backend.buf_register_size(&td, span + 4096);
    assert(libmufile_buf_register(NULL, size) == 0);
    assert(registered_size == span + 256 * 1024);
    return 0;
}
""", encoding="ascii")
        binary = self.path / "registration-test"
        flags = (["-Wl,-dead_strip"]
                 if sys.platform == "darwin" else ["-Wl,--gc-sections"])
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-D_GNU_SOURCE", "-O2", "-ffunction-sections", "-fdata-sections",
            "-include", str(BUILD / "config-host.h"),
            "-I", str(ROOT), "-I", str(self.sdk / "include"),
            str(source), "-o", str(binary)] + flags,
            check=True, text=True)
        subprocess.run([str(binary)], check=True)

    def test_dynamic_engine_has_unique_symbol(self):
        obj = self.path / "libmufile-dynamic.o"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-D_GNU_SOURCE", "-DCONFIG_DYNAMIC_ENGINES",
            "-include", str(BUILD / "config-host.h"),
            "-I", str(ROOT), "-I", str(self.sdk / "include"),
            "-c", str(ROOT / "engines/libmufile.c"), "-o", str(obj)],
            check=True, text=True)
        symbols = subprocess.check_output(["nm", "-g", str(obj)], text=True)
        names = [line.split()[-1].lstrip("_") for line in symbols.splitlines()
                 if line.split()]
        self.assertIn("libmufile", names)
        self.assertNotIn("ioengine", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
