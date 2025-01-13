#!/usr/bin/env python3
"""
# client_server.py
#
# Test fio's client/server mode.
#
# USAGE
# see python3 client_server.py --help
#
# EXAMPLES
# python3 t/client_server.py
# python3 t/client_server.py -f ./fio
#
# REQUIREMENTS
# Python 3.6
#
# This will start fio server instances listening on the interfaces below and
# will break if any ports are already occupied.
#
#
"""
import os
import sys
import time
import locale
import logging
import argparse
import tempfile
import subprocess
import configparser
from pathlib import Path
from fiotestlib import FioJobCmdTest, run_fio_tests


SERVER_LIST = [
            ",8765",
            ",8766",
            ",8767",
            ",8768",
        ]

PIDFILE_LIST = []

class ClientServerTest(FioJobCmdTest):
    """
    Client/sever test class.
    """

    def setup(self, parameters):
        """Setup a test."""

        fio_args = [
            f"--output={self.filenames['output']}",
            f"--output-format={self.fio_opts['output-format']}",
        ]
        for server in self.fio_opts['servers']:
            option = f"--client={server['client']}"
            fio_args.append(option)
            fio_args.append(server['jobfile'])

        super().setup(fio_args)



class ClientServerTestGlobalSingle(ClientServerTest):
    """
    Client/sever test class.
    One server connection only.
    The job file may or may not have a global section.
    """

    def check_result(self):
        super().check_result()

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(self.fio_opts['servers'][0]['jobfile'])

        if not config.has_section('global'):
            if len(self.json_data['global options']) > 0:
                self.failure_reason = f"{self.failure_reason} non-empty 'global options' dictionary found with no global section in job file."
                self.passed = False
            return

        if len(self.json_data['global options']) == 0:
            self.failure_reason = f"{self.failure_reason} empty 'global options' dictionary found with no global section in job file."
            self.passed = False

        # Now make sure job file global section matches 'global options'
        # in JSON output
        job_file_global = dict(config['global'])
        for key, value in job_file_global.items():
            if value is None:
                job_file_global[key] = ""
        if job_file_global != self.json_data['global options']:
            self.failure_reason = f"{self.failure_reason} 'global options' dictionary does not match global section in job file."
            self.passed = False


class ClientServerTestGlobalMultiple(ClientServerTest):
    """
    Client/sever test class.
    Multiple server connections.
    Job files may or may not have a global section.
    """

    def check_result(self):
        super().check_result()

        #
        # For each job file, check if it has a global section
        # If so, make sure the 'global options' array has
        # as element for it.
        # At the end, make sure the total number of elements matches the number
        # of job files with global sections.
        #

        global_sections = 0
        for server in self.fio_opts['servers']:
            config = configparser.ConfigParser(allow_no_value=True)
            config.read(server['jobfile'])

            if not config.has_section('global'):
                continue

            global_sections += 1

            # this can only parse one server spec format
            [hostname, port] = server['client'].split(',')

            match = None
            for global_opts in self.json_data['global options']:
                if 'hostname' not in global_opts:
                    continue
                if 'port' not in global_opts:
                    continue
                if global_opts['hostname'] == hostname and int(global_opts['port']) == int(port):
                    match = global_opts
                    break

            if not match:
                self.failure_reason = f"{self.failure_reason} matching 'global options' element not found for {hostname}, {port}."
                self.passed = False
                continue

            del match['hostname']
            del match['port']

            # Now make sure job file global section matches 'global options'
            # in JSON output
            job_file_global = dict(config['global'])
            for key, value in job_file_global.items():
                if value is None:
                    job_file_global[key] = ""
            if job_file_global != match:
                self.failure_reason += " 'global options' dictionary does not match global section in job file."
                self.passed = False
            else:
                logging.debug("Job file global section matches 'global options' array element %s", server['client'])

        if global_sections != len(self.json_data['global options']):
            self.failure_reason = f"{self.failure_reason} mismatched number of elements in 'global options' array."
            self.passed = False
        else:
            logging.debug("%d elements in global options array as expected", global_sections)


class ClientServerTestAllClientsLat(ClientServerTest):
    """
    Client/sever test class.
    Make sure the "All clients" job has latency percentile data.
    Assumes that a job named 'test' is run with no global section.
    Only check read data.
    """

    def check_result(self):
        super().check_result()

        config = configparser.ConfigParser(allow_no_value=True)
        config.read(self.fio_opts['servers'][0]['jobfile'])

        lats = { 'clat': True, 'lat': False, 'slat': False }
        for key in lats:
            opt = f"{key}_percentiles"
            if opt in config.options('test'):
                lats[key] = config.getboolean('test', opt)
                logging.debug("%s set to %s", opt, lats[key])

        all_clients = None
        client_stats = self.json_data['client_stats']
        for client in client_stats:
            if client['jobname'] == "All clients":
                all_clients = client
                break

        if not all_clients:
            self.failure_reason = f"{self.failure_reason} Could not find 'All clients' output"
            self.passed = False

        for key, value in lats.items():
            if value:
                if 'percentile' not in all_clients['read'][f"{key}_ns"]:
                    self.failure_reason += f" {key} percentiles not found"
                    self.passed = False
                    break

                logging.debug("%s percentiles found as expected", key)
            else:
                if 'percentile' in all_clients['read'][f"{key}_ns"]:
                    self.failure_reason += f" {key} percentiles found unexpectedly"
                    self.passed = False
                    break

                logging.debug("%s percentiles appropriately not found", key)



TEST_LIST = [
    {   # Smoke test
        "test_id": 1,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0, # index into the SERVER_LIST array
                        "jobfile": "test01.fio",
                    },
                ]
            },
        "test_class": ClientServerTest,
    },
    {   # try another client
        "test_id": 2,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 1,
                        "jobfile": "test01.fio",
                    },
                ]
            },
        "test_class": ClientServerTest,
    },
    {   # single client global section
        "test_id": 3,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 2,
                        "jobfile": "test01.fio",
                    },
                ]
            },
        "test_class": ClientServerTestGlobalSingle,
    },
    {   # single client no global section
        "test_id": 4,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 3,
                        "jobfile": "test04-noglobal.fio",
                    },
                ]
            },
        "test_class": ClientServerTestGlobalSingle,
    },
    {   # multiple clients, some with global, some without
        "test_id": 5,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test04-noglobal.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test01.fio",
                    },
                    {
                        "client" : 2,
                        "jobfile": "test04-noglobal.fio",
                    },
                    {
                        "client" : 3,
                        "jobfile": "test01.fio",
                    },
                ]
            },
        "test_class": ClientServerTestGlobalMultiple,
    },
    {   # multiple clients, all with global sections
        "test_id": 6,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test01.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test01.fio",
                    },
                    {
                        "client" : 2,
                        "jobfile": "test01.fio",
                    },
                    {
                        "client" : 3,
                        "jobfile": "test01.fio",
                    },
                ]
            },
        "test_class": ClientServerTestGlobalMultiple,
    },
    {   # Enable submission latency
        "test_id": 7,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test07-slat.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test07-slat.fio",
                    },
                ]
            },
        "test_class": ClientServerTestAllClientsLat,
    },
    {   # Enable completion latency
        "test_id": 8,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test08-clat.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test08-clat.fio",
                    },
                ]
            },
        "test_class": ClientServerTestAllClientsLat,
    },
    {   # Enable total latency
        "test_id": 9,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test09-lat.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test09-lat.fio",
                    },
                ]
            },
        "test_class": ClientServerTestAllClientsLat,
    },
    {   # Disable completion latency
        "test_id": 10,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test10-noclat.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test10-noclat.fio",
                    },
                ]
            },
        "test_class": ClientServerTestAllClientsLat,
    },
    {   # Enable submission, completion, total latency
        "test_id": 11,
        "fio_opts": {
            "output-format": "json",
            "servers": [
                    {
                        "client" : 0,
                        "jobfile": "test11-alllat.fio",
                    },
                    {
                        "client" : 1,
                        "jobfile": "test11-alllat.fio",
                    },
                ]
            },
        "test_class": ClientServerTestAllClientsLat,
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
    args = parser.parse_args()

    return args


def start_servers(fio_path, servers=SERVER_LIST):
    """Start servers for our tests."""

    for server in servers:
        tmpfile = tempfile.mktemp()
        cmd = [fio_path, f"--server={server}", f"--daemonize={tmpfile}"]
        cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                   encoding=locale.getpreferredencoding())
        if cmd_result.returncode != 0:
            logging.error("Unable to start server on %s: %s", server, cmd_result.stderr)
            return False

        logging.debug("Started server %s", server)
        PIDFILE_LIST.append(tmpfile)

    return True


def stop_servers(pidfiles=PIDFILE_LIST):
    """Stop running fio server invocations."""

    for pidfile in pidfiles:
        with open(pidfile, "r", encoding=locale.getpreferredencoding()) as file:
            pid = file.read().strip()

        cmd = ["kill", f"{pid}"]
        cmd_result = subprocess.run(cmd, capture_output=True, check=False,
                                   encoding=locale.getpreferredencoding())
        if cmd_result.returncode != 0:
            logging.error("Unable to kill server with PID %s: %s", pid, cmd_result.stderr)
            return False
        logging.debug("Sent stop signal to PID %s", pid)

    return True


def main():
    """Run tests for fio's client/server mode."""

    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    artifact_root = args.artifact_root if args.artifact_root else \
        f"client_server-test-{time.strftime('%Y%m%d-%H%M%S')}"
    os.mkdir(artifact_root)
    print(f"Artifact directory is {artifact_root}")

    if args.fio:
        fio_path = str(Path(args.fio).absolute())
    else:
        fio_path = os.path.join(os.path.dirname(__file__), '../fio')
    print(f"fio path is {fio_path}")

    if not start_servers(fio_path):
        sys.exit(1)
    print("Servers started")

    job_path = os.path.join(os.path.dirname(__file__), "client_server")
    for test in TEST_LIST:
        opts = test['fio_opts']
        for server in opts['servers']:
            server['client'] = SERVER_LIST[server['client']]
            server['jobfile'] = os.path.join(job_path, server['jobfile'])

    test_env = {
              'fio_path': fio_path,
              'fio_root': str(Path(__file__).absolute().parent.parent),
              'artifact_root': artifact_root,
              'basename': 'client_server',
              }

    _, failed, _ = run_fio_tests(TEST_LIST, test_env, args)

    stop_servers()
    sys.exit(failed)

if __name__ == '__main__':
    main()
