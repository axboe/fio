#!/usr/bin/env python3
#
# Copyright 2024 Samsung Electronics Co., Ltd All Rights Reserved
#
# For conditions of distribution and use, see the accompanying COPYING file.
#
"""
# nvmept_fdp.py
#
# Test fio's io_uring_cmd ioengine with NVMe pass-through FDP write commands.
#
# USAGE
# see python3 nvmept_fdp.py --help
#
# EXAMPLES
# python3 t/nvmept_fdp.py --dut /dev/ng0n1
# python3 t/nvmept_fdp.py --dut /dev/ng1n1 -f ./fio
#
# REQUIREMENTS
# Python 3.6
# Device formatted with LBA data size 4096 bytes
# Device with at least five placement IDs
#
# WARNING
# This is a destructive test
"""
import os
import sys
import json
import time
import locale
import logging
import argparse
import subprocess
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests
from fiotestcommon import SUCCESS_NONZERO

# This needs to match FIO_MAX_DP_IDS and DP_MAX_SCHEME_ENTRIES in
# dataplacement.h
FIO_MAX_DP_IDS = 128
DP_MAX_SCHEME_ENTRIES = 32

class FDPTest(FioJobCmdTest):
    """
    NVMe pass-through test class. Check to make sure output for selected data
    direction(s) is non-zero and that zero data appears for other directions.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            "--name=nvmept-fdp",
            "--ioengine=io_uring_cmd",
            "--cmd_type=nvme",
            "--randrepeat=0",
            f"--filename={self.fio_opts['filename']}",
            f"--rw={self.fio_opts['rw']}",
            f"--output={self.filenames['output']}",
            f"--output-format={self.fio_opts['output-format']}",
        ]

        for opt in ['fixedbufs', 'nonvectored', 'force_async', 'registerfiles',
                    'sqthread_poll', 'sqthread_poll_cpu', 'hipri', 'nowait',
                    'time_based', 'runtime', 'verify', 'io_size', 'num_range',
                    'iodepth', 'iodepth_batch', 'iodepth_batch_complete',
                    'size', 'rate', 'bs', 'bssplit', 'bsrange', 'randrepeat',
                    'buffer_pattern', 'verify_pattern', 'offset', 'fdp',
                    'fdp_pli', 'fdp_pli_select', 'dataplacement', 'plid_select',
                    'plids', 'dp_scheme', 'number_ios', 'read_iolog']:
            if opt in self.fio_opts:
                option = f"--{opt}={self.fio_opts[opt]}"
                fio_args.append(option)

        super().setup(fio_args)


    def check_result(self):
        try:
            self._check_result()
        finally:
            if not update_all_ruhs(self.fio_opts['filename']):
                logging.error("Could not reset device")
            if not check_all_ruhs(self.fio_opts['filename']):
                logging.error("Reclaim units have inconsistent RUAMW values")


    def _check_result(self):

        super().check_result()

        if 'rw' not in self.fio_opts or \
                not self.passed or \
                'json' not in self.fio_opts['output-format']:
            return

        job = self.json_data['jobs'][0]
        rw_fio_opts = self.fio_opts['rw'].split(':')[0]

        if rw_fio_opts in ['read', 'randread']:
            self.passed = self.check_all_ddirs(['read'], job)
        elif rw_fio_opts in ['write', 'randwrite']:
            if 'verify' not in self.fio_opts:
                self.passed = self.check_all_ddirs(['write'], job)
            else:
                self.passed = self.check_all_ddirs(['read', 'write'], job)
        elif rw_fio_opts in ['trim', 'randtrim']:
            self.passed = self.check_all_ddirs(['trim'], job)
        elif rw_fio_opts in ['readwrite', 'randrw']:
            self.passed = self.check_all_ddirs(['read', 'write'], job)
        elif rw_fio_opts in ['trimwrite', 'randtrimwrite']:
            self.passed = self.check_all_ddirs(['trim', 'write'], job)
        else:
            logging.error("Unhandled rw value %s", self.fio_opts['rw'])
            self.passed = False

        if 'iodepth' in self.fio_opts:
            # We will need to figure something out if any test uses an iodepth
            # different from 8
            if job['iodepth_level']['8'] < 95:
                logging.error("Did not achieve requested iodepth")
                self.passed = False
            else:
                logging.debug("iodepth 8 target met %s", job['iodepth_level']['8'])


class FDPMultiplePLIDTest(FDPTest):
    """
    Write to multiple placement IDs.
    """

    def setup(self, parameters):
        mapping = {
                    'nruhsd': FIO_FDP_NUMBER_PLIDS,
                    'max_ruamw': FIO_FDP_MAX_RUAMW,
                    'maxplid': FIO_FDP_NUMBER_PLIDS-1,
                    # parameters for 400, 401 tests
                    'hole_size': 64*1024,
                    'nios_for_scheme': min(FIO_FDP_NUMBER_PLIDS//2, DP_MAX_SCHEME_ENTRIES),
                }
        if 'number_ios' in self.fio_opts and isinstance(self.fio_opts['number_ios'], str):
            self.fio_opts['number_ios'] = eval(self.fio_opts['number_ios'].format(**mapping))
        if 'bs' in self.fio_opts and isinstance(self.fio_opts['bs'], str):
            self.fio_opts['bs'] = eval(self.fio_opts['bs'].format(**mapping))
        if 'rw' in self.fio_opts and isinstance(self.fio_opts['rw'], str):
            self.fio_opts['rw'] = self.fio_opts['rw'].format(**mapping)
        if 'plids' in self.fio_opts and isinstance(self.fio_opts['plids'], str):
            self.fio_opts['plids'] = self.fio_opts['plids'].format(**mapping)
        if 'fdp_pli' in self.fio_opts and isinstance(self.fio_opts['fdp_pli'], str):
            self.fio_opts['fdp_pli'] = self.fio_opts['fdp_pli'].format(**mapping)

        super().setup(parameters)
        
        if 'dp_scheme' in self.fio_opts:
            scheme_path = os.path.join(self.paths['test_dir'], self.fio_opts['dp_scheme'])
            with open(scheme_path, mode='w') as f:
                for i in range(mapping['nios_for_scheme']):
                    f.write(f'{mapping["hole_size"] * 2 * i}, {mapping["hole_size"] * 2 * (i+1)}, {i}\n')

        if 'read_iolog' in self.fio_opts:
            read_iolog_path = os.path.join(self.paths['test_dir'], self.fio_opts['read_iolog'])
            with open(read_iolog_path, mode='w') as f:
                f.write('fio version 2 iolog\n')
                f.write(f'{self.fio_opts["filename"]} add\n')
                f.write(f'{self.fio_opts["filename"]} open\n')

                for i in range(mapping['nios_for_scheme']):
                    f.write(f'{self.fio_opts["filename"]} write {mapping["hole_size"] * 2 * i} {mapping["hole_size"]}\n')

                f.write(f'{self.fio_opts["filename"]} close')
 
    def _check_result(self):
        if 'fdp_pli' in self.fio_opts:
            plid_list = self.fio_opts['fdp_pli'].split(',')
        elif 'plids' in self.fio_opts:
            plid_list = self.fio_opts['plids'].split(',')
        else:
            plid_list = [str(i) for i in range(FIO_FDP_NUMBER_PLIDS)]

        range_ids = []
        for plid in plid_list:
            if '-' in plid:
                [start, end] = plid.split('-')
                range_ids.extend(list(range(int(start), int(end)+1)))
            else:
                range_ids.append(int(plid))

        plid_list = sorted(range_ids)
        logging.debug("plid_list: %s", str(plid_list))

        fdp_status = get_fdp_status(self.fio_opts['filename'])

        select = "roundrobin"
        if 'fdp_pli_select' in self.fio_opts:
            select = self.fio_opts['fdp_pli_select']
        elif 'plid_select' in self.fio_opts:
            select = self.fio_opts['plid_select']

        if select == "roundrobin":
            self._check_robin(plid_list, fdp_status)
        elif select == "random":
            self._check_random(plid_list, fdp_status)
        elif select == "scheme":
            self._check_scheme(plid_list, fdp_status)
        else:
            logging.error("Unknown plid selection strategy %s", select)
            self.passed = False
        
        super()._check_result()

    def _check_robin(self, plid_list, fdp_status):
        """
        With round robin we can know exactly how many writes each PLID will
        receive.
        """
        ruamw = [FIO_FDP_MAX_RUAMW] * FIO_FDP_NUMBER_PLIDS

        number_ios = self.fio_opts['number_ios'] % (len(plid_list)*FIO_FDP_MAX_RUAMW)
        remainder = int(number_ios % len(plid_list))
        whole = int((number_ios - remainder) / len(plid_list))
        logging.debug("PLIDs in the list should show they have received %d writes; %d PLIDs will receive one extra",
                      whole, remainder)

        for plid in plid_list:
            ruamw[plid] -= whole
            if remainder:
                ruamw[plid] -= 1
                remainder -= 1
        logging.debug("Expected ruamw values: %s", str(ruamw))

        for idx, ruhs in enumerate(fdp_status['ruhss']):
            if idx >= FIO_FDP_NUMBER_PLIDS:
                break

            if ruhs['ruamw'] != ruamw[idx]:
                logging.error("RUAMW mismatch with idx %d, pid %d, expected %d, observed %d", idx,
                              ruhs['pid'], ruamw[idx], ruhs['ruamw'])
                self.passed = False
                break

            logging.debug("RUAMW match with idx %d, pid %d: ruamw=%d", idx, ruhs['pid'], ruamw[idx])

    def _check_random(self, plid_list, fdp_status):
        """
        With random selection, a set of PLIDs will receive all the write
        operations and the remainder will be untouched.
        """

        total_ruamw = 0
        for plid in plid_list:
            total_ruamw += fdp_status['ruhss'][plid]['ruamw']

        expected = len(plid_list) * FIO_FDP_MAX_RUAMW - self.fio_opts['number_ios']
        if total_ruamw != expected:
            logging.error("Expected total ruamw %d for plids %s, observed %d", expected,
                          str(plid_list), total_ruamw)
            self.passed = False
        else:
            logging.debug("Observed expected total ruamw %d for plids %s", expected, str(plid_list))

        for idx, ruhs in enumerate(fdp_status['ruhss']):
            if idx in plid_list:
                continue
            if ruhs['ruamw'] != FIO_FDP_MAX_RUAMW:
                logging.error("Unexpected ruamw %d for idx %d, pid %d, expected %d", ruhs['ruamw'],
                              idx, ruhs['pid'], FIO_FDP_MAX_RUAMW)
                self.passed = False
            else:
                logging.debug("Observed expected ruamw %d for idx %d, pid %d", ruhs['ruamw'], idx,
                              ruhs['pid'])

    def _check_scheme(self, plid_list, fdp_status):
        """
        With scheme selection, a set of PLIDs touched by the scheme
        """

        PLID_IDX_POS = 2
        plid_list_from_scheme = set()

        scheme_path = os.path.join(self.paths['test_dir'], self.fio_opts['dp_scheme'])

        with open(scheme_path) as f:
            lines = f.readlines()
            for line in lines:
                line_elem = line.strip().replace(' ', '').split(',')
                plid_list_from_scheme.add(int(line_elem[PLID_IDX_POS]))

        logging.debug(f'plid_list_from_scheme: {plid_list_from_scheme}')

        for idx, ruhs in enumerate(fdp_status['ruhss']):
            if ruhs['pid'] in plid_list_from_scheme:
                if ruhs['ruamw'] == FIO_FDP_MAX_RUAMW:
                    logging.error("pid %d should be touched by the scheme. But ruamw of it(%d) equals to %d",
                                    ruhs['pid'], ruhs['ruamw'], FIO_FDP_MAX_RUAMW)
                    self.passed = False
                else:
                    logging.debug("pid %d should be touched by the scheme. ruamw of it(%d) is under %d",
                                    ruhs['pid'], ruhs['ruamw'], FIO_FDP_MAX_RUAMW)
            else:
                if ruhs['ruamw'] == FIO_FDP_MAX_RUAMW:
                    logging.debug("pid %d should not be touched by the scheme. ruamw of it(%d) equals to %d",
                                    ruhs['pid'], ruhs['ruamw'], FIO_FDP_MAX_RUAMW)
                else:
                    logging.error("pid %d should not be touched by the scheme. But ruamw of it(%d) is under %d",
                                    ruhs['pid'], ruhs['ruamw'], FIO_FDP_MAX_RUAMW)
                    self.passed = False


class FDPSinglePLIDTest(FDPTest):
    """
    Write to a single placement ID only.
    """

    def _check_result(self):
        if 'plids' in self.fio_opts:
            plid = self.fio_opts['plids']
        elif 'fdp_pli' in self.fio_opts:
            plid = self.fio_opts['fdp_pli']
        else:
            plid = 0

        fdp_status = get_fdp_status(self.fio_opts['filename'])
        ruamw = fdp_status['ruhss'][plid]['ruamw']
        lba_count = self.fio_opts['number_ios']

        if FIO_FDP_MAX_RUAMW - lba_count != ruamw:
            logging.error("FDP accounting mismatch for plid %d; expected ruamw %d, observed %d",
                          plid, FIO_FDP_MAX_RUAMW - lba_count, ruamw)
            self.passed = False
        else:
            logging.debug("FDP accounting as expected for plid %d; ruamw = %d", plid, ruamw)

        super()._check_result()


class FDPReadTest(FDPTest):
    """
    Read workload test.
    """

    def _check_result(self):
        ruamw = check_all_ruhs(self.fio_opts['filename'])

        if ruamw != FIO_FDP_MAX_RUAMW:
            logging.error("Read workload affected FDP ruamw")
            self.passed = False
        else:
            logging.debug("Read workload did not disturb FDP ruamw")
            super()._check_result()


def get_fdp_status(dut):
    """
    Run the nvme-cli command to obtain FDP status and return result as a JSON
    object.
    """

    cmd = f"sudo nvme fdp status --output-format=json {dut}"
    cmd = cmd.split(' ')
    cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                encoding=locale.getpreferredencoding())

    if cmd_result.returncode != 0:
        logging.error("Error obtaining device %s FDP status: %s", dut, cmd_result.stderr)
        return False

    return json.loads(cmd_result.stdout)


def update_ruh(dut, plid):
    """
    Update reclaim unit handles with specified ID(s). This tells the device to
    point the RUH to a new (empty) reclaim unit.
    """

    ids = ','.join(plid) if isinstance(plid, list) else plid
    cmd = f"nvme fdp update --pids={ids} {dut}"
    cmd = cmd.split(' ')
    cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                encoding=locale.getpreferredencoding())

    if cmd_result.returncode != 0:
        logging.error("Error updating RUH %s ID(s) %s", dut, ids)
        return False

    return True


def update_all_ruhs(dut):
    """
    Update all reclaim unit handles on the device.
    """

    fdp_status = get_fdp_status(dut)
    for ruhs in fdp_status['ruhss']:
        if not update_ruh(dut, ruhs['pid']):
            return False

    return True


def check_all_ruhs(dut):
    """
    Check that all RUHs have the same value for reclaim unit available media
    writes (RUAMW).  Return the RUAMW value.
    """

    fdp_status = get_fdp_status(dut)
    ruh_status = fdp_status['ruhss']

    ruamw = ruh_status[0]['ruamw']
    for ruhs in ruh_status:
        if ruhs['ruamw'] != ruamw:
            logging.error("RUAMW mismatch: found %d, expected %d", ruhs['ruamw'], ruamw)
            return False

    return ruamw


TEST_LIST = [
    # Write one LBA to one PLID using both the old and new sets of options
    ## omit fdp_pli_select/plid_select
    {
        "test_id": 1,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 2,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 3,
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    ## fdp_pli_select/plid_select=roundrobin
    {
        "test_id": 3,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "fdp_pli_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 4,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 3,
            "plid_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    ## fdp_pli_select/plid_select=random
    {
        "test_id": 5,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 6,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 1,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 3,
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    # Write four LBAs to one PLID using both the old and new sets of options
    ## omit fdp_pli_select/plid_select
    {
        "test_id": 7,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 1,
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 8,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 1,
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    ## fdp_pli_select/plid_select=roundrobin
    {
        "test_id": 9,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 1,
            "fdp_pli_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 10,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 1,
            "plid_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    ## fdp_pli_select/plid_select=random
    {
        "test_id": 11,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 1,
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    {
        "test_id": 12,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 4,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 1,
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    # Just a regular write without FDP directive--should land on plid 0
    {
        "test_id": 13,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": 19,
            "verify": "crc32c",
            "output-format": "json",
            },
        "test_class": FDPSinglePLIDTest,
    },
    # Read workload
    {
        "test_id": 14,
        "fio_opts": {
            "rw": 'randread',
            "bs": 4096,
            "number_ios": 19,
            "output-format": "json",
            },
        "test_class": FDPReadTest,
    },
    # write to multiple PLIDs using round robin to select PLIDs
    ## write to all PLIDs using old and new sets of options
    {
        "test_id": 100,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "2*{nruhsd}+3",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 101,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "2*{nruhsd}+3",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plid_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    ## write to a subset of PLIDs using old and new sets of options
    {
        "test_id": 102,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{nruhsd}+1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "1,3",
            "fdp_pli_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 103,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{nruhsd}+1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": "1,3",
            "plid_select": "roundrobin",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    # write to multiple PLIDs using random selection of PLIDs
    ## write to all PLIDs using old and new sets of options
    {
        "test_id": 200,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 201,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    ## write to a subset of PLIDs using old and new sets of options
    {
        "test_id": 202,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "1,3,4",
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 203,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": "1,3,4",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    ### use 3-4 to specify plids
    {
        "test_id": 204,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "1,3-4",
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 205,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": "1,3-4",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    ### use 1-3 to specify plids
    {
        "test_id": 206,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "1-3",
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 207,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": "1-3",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    ### use multiple ranges to specify plids
    {
        "test_id": 208,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "1-2,3-3",
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 209,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": "1-2,3-3",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 210,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "0-{maxplid}",
            "fdp_pli_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 211,
        "fio_opts": {
            "rw": 'randwrite',
            "bs": 4096,
            "number_ios": "{max_ruamw}-1",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "fdp_pli": "0-{maxplid}",
            "plid_select": "random",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    # Specify invalid options fdp=1 and dataplacement=none
    {
        "test_id": 300,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "output-format": "normal",
            "dataplacement": "none",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    # Specify invalid options fdp=1 and dataplacement=streams
    {
        "test_id": 301,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "output-format": "normal",
            "dataplacement": "streams",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    # Specify invalid options related to dataplacement scheme
    ## using old and new sets of options
    {
        "test_id": 302,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": 3,
            "fdp_pli_select": "scheme",
            "output-format": "normal",
        },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 303,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plids": 3,
            "plid_select": "scheme",
            "output-format": "normal",
        },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    ## Specify invalid ranges with start > end
    {
        "test_id": 304,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "plids": "3-1",
            "output-format": "normal",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 305,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "3-1",
            "output-format": "normal",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    ## Specify too many plids
    {
        "test_id": 306,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "plids": "0-65535",
            "output-format": "normal",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    {
        "test_id": 307,
        "fio_opts": {
            "rw": 'write',
            "bs": 4096,
            "io_size": 4096,
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli": "0-65535",
            "output-format": "normal",
            },
        "test_class": FDPTest,
        "success": SUCCESS_NONZERO,
    },
    # write to multiple PLIDs using scheme selection of PLIDs
    ## using old and new sets of options
    {
        "test_id": 400,
        "fio_opts": {
            "rw": "write:{hole_size}",
            "bs": "{hole_size}",
            "number_ios": "{nios_for_scheme}",
            "verify": "crc32c",
            "fdp": 1,
            "fdp_pli_select": "scheme",
            "dp_scheme": "lba.scheme",            
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    {
        "test_id": 401,
        "fio_opts": {
            "rw": "write:{hole_size}",
            "bs": "{hole_size}",
            "number_ios": "{nios_for_scheme}",
            "verify": "crc32c",
            "dataplacement": "fdp",
            "plid_select": "scheme",
            "dp_scheme": "lba.scheme",
            "output-format": "json",
            },
        "test_class": FDPMultiplePLIDTest,
    },
    # check whether dataplacement works while replaying iologs
    {
        "test_id": 402,
        "fio_opts": {
            "rw": "write:{hole_size}",
            "bs": "{hole_size}",
            "number_ios": "{nios_for_scheme}",
            "verify": "crc32c",
            "read_iolog": "iolog",
            "dataplacement": "fdp",
            "plid_select": "scheme",
            "dp_scheme": "lba.scheme",
            "output-format": "json",
        },
        "test_class": FDPMultiplePLIDTest,
    },
]

def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Enable debug messages', action='store_true')
    parser.add_argument('-f', '--fio', help='path to file executable (e.g., ./fio)')
    parser.add_argument('-a', '--artifact-root', help='artifact root directory')
    parser.add_argument('-s', '--skip', nargs='+', type=int,
                        help='list of test(s) to skip')
    parser.add_argument('-o', '--run-only', nargs='+', type=int,
                        help='list of test(s) to run, skipping all others')
    parser.add_argument('--dut', help='target NVMe character device to test '
                        '(e.g., /dev/ng0n1). WARNING: THIS IS A DESTRUCTIVE TEST', required=True)
    args = parser.parse_args()

    return args


FIO_FDP_MAX_RUAMW = 0
FIO_FDP_NUMBER_PLIDS = 0

def main():
    """Run tests using fio's io_uring_cmd ioengine to send NVMe pass through commands."""
    global FIO_FDP_MAX_RUAMW
    global FIO_FDP_NUMBER_PLIDS

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"nvmept-fdp-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = 'fio'
    print(f"fio path is {fio_path}")

    for test in TEST_LIST:
        test['fio_opts']['filename'] = args.dut

    fdp_status = get_fdp_status(args.dut)
    FIO_FDP_NUMBER_PLIDS = min(fdp_status['nruhsd'], 128)
    update_all_ruhs(args.dut)
    FIO_FDP_MAX_RUAMW = check_all_ruhs(args.dut)
    if not FIO_FDP_MAX_RUAMW:
        sys.exit(-1)

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'nvmept-fdp',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)
    sys.exit(failed)


if __name__ == '__main__':
    main()
