#!/usr/bin/env python3
"""
Simple launcher utility for starting an interactive Python session with a MaglevSystemCommandLine object.
"""
import argparse
import code
import getpass
import logging
import re
import subprocess
import sys

try:
    GIT_ROOT = subprocess.Popen(
        ['git', 'rev-parse', '--show-toplevel'],
        stdout=subprocess.PIPE,
    ).communicate()[0].rstrip().decode('utf-8')
    sys.path.append(GIT_ROOT)
    from services.maglev_cli.maglevclihandler import MaglevSystemCommandLine as MSCL
except ImportError:
    import traceback
    traceback.print_exc()
    print('Failed to import MaglevSystemCommandLine utility!')
    exit(1)

DEFAULT_USERNAME = 'maglev'
DEFAULT_NODEPORT = 2222


def parse_args():
    """ Parse CLI arguments """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument(
        '-x', '--use-persistent-connection',
        action='store_true',
        help='If set, will maintain a persistent SSH connection to the maglev appliance.  By default, will send each ' \
        'command in its own session.',
    )
    parser.add_argument(
        'node_address',
        type=str,
        help='The address of the maglev appliance.  In the form [username@]node_ip[:port].  By default, assumes a ' \
        'username of "maglev" and a port of "2222".',
    )
    parser.add_argument(
        '-u', '--admin-username',
        nargs='?',
        default='admin',
        type=str,
        help='Admin username for the maglev appliance (default: "admin").',
    )
    parser.add_argument(
        '-p', '--admin-password',
        nargs='?',
        default=None,
        type=str,
        help='Admin password for the maglev appliance (default: same as user password).',
    )
    parser.add_argument(
        '-t', '--timeout',
        nargs='?',
        default=30,
        type=float,
        help='Maximum time to wait for a response before throwing a timeout exception.',
    )
    return parser.parse_args()


def launch_mscl():
    """ Launch MSCL utility """
    args = parse_args()
    username, node_ip, port = re.match(r'^(?:(\w+)@)?([a-zA-Z0-9.]+)(?::(\d+))?', args.node_address).groups()
    password = getpass.getpass('Password for {}: '.format(args.node_address))
    if not username:
        username = DEFAULT_USERNAME
    if not port:
        port = DEFAULT_NODEPORT

    logger_handler = logging.StreamHandler(sys.stdout)
    logger_formatter = logging.Formatter('@MSCL: %(asctime)s [%(levelname)s] %(message)s')
    logger_handler.setFormatter(logger_formatter)
    logger = logging.getLogger(MSCL.__module__)
    logger.addHandler(logger_handler)
    logger.setLevel(logging.DEBUG)
    MSCL.default_logger = logger

    mscl = MSCL(
        node_ip, username, password, port,
        admin_username=args.admin_username,
        admin_password=args.admin_password,
        default_timeout=args.timeout,
        use_persistent_connection=args.use_persistent_connection,
    )
    return mscl


if __name__ == '__main__':
    mscl = launch_mscl()
    print('==============================================')
    print('  MSCL instantiated as local variable "mscl"')
    print('==============================================')
    code.interact(local=locals())


