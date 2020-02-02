#!/usr/bin/env python3

##
##  Karkinos - b0bb
##
##  https://twitter.com/0xb0bb
##  https://github.com/0xb0bb/karkinos
##

import argparse
import sqlite3
import json
import sys
import glob
import os
import requests
import shutil
import time
import shlex
import string
import re

CONN   = None
DB     = None

TIME   = ((60 * 60) * 24) * 30
INDEX  = None
FILTER = {
    'arch':   None,
    'distro': None,
}

DESC = """description:
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

libraries indexed:
  - glibc
  - libstdc++

commands:
  - find                 find a library by symbol offsets, file, build id or file hash
  - dump                 dump symbols/gadgets for a given library
  - info                 print some information about a specific library
  - update               check for updates to the database
  - version              display version information and exit
"""

EPILOG = """examples:
  PROGNAME find fgets b20 puts 9c0 fwrite 8a0
  PROGNAME find 50390b2ae8aaa73c47745040f54e602f
  PROGNAME find b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0
  PROGNAME find /lib/x86_64-linux-gnu/libc.so.6
  PROGNAME --arch arm --endian big find system 440
  PROGNAME --distro ubuntu fgets b20 puts 9c0
  PROGNAME dump centos_glibc-2.12-1.107.el6_4.2.x86_64
  PROGNAME dump opensuse_glibc-2.19-16.9.1.i686 fgets system str_bin_sh
  PROGNAME info ubuntu_libc6-udeb_2.27-3ubuntu1_amd64
  PROGNAME update
""".replace('PROGNAME', sys.argv[0])


def get_lib(name):

    DB.execute(
        'SELECT' +
            '`libs`.`rowid`    as `id`,'         +
            '`libs`.`name`     as `name`,'       +
            '`distros`.`name`  as `distro`,'     +
            '`archs`.`display` as `arch`,'       +
            '`libs`.`version`  as `version`,'    +
            '`libs`.`variant`  as `variant`,'    +
            '`libs`.`build_id` as `build_id`,'   +
            '`libs`.`md5`      as `hash_md5`,'   +
            '`libs`.`sha1`     as `hash_sha1`,'  +
            '`libs`.`sha256`   as `hash_sha256`' +
        'FROM' +
            '`libs`,'    +
            '`distros`,' +
            '`archs`'    +
        'WHERE' +
            '`libs`.`name`    = ? AND '                +
            '`distros`.`rowid` = `libs`.`distro` AND ' +
            '`archs`.`rowid`   = `libs`.`arch`',
    (name,))

    res = DB.fetchone()
    if not res:
        return None

    ret = {
        'id':         res[0],
        'name':       res[1],
        'distro':     res[2],
        'arch':       res[3],
        'version':    res[4],
        'variant':    res[5],
        'build_id':   res[6],
        'packages':   get_packages(res[0]),
        'symbols':    get_symbols(res[0]),
        'gadgets':    get_gadgets(res[0]),
        'hash': {
            'md5':    res[7],
            'sha1':   res[8],
            'sha256': res[9]
        }
    }

    return ret


def get_symbols(libid):

    DB.execute(
        'SELECT' +
            '`symbol_offsets`.`rowid`  as `id`,'     +
            '`symbol_types`.`name`     as `type`,'   +
            '`symbols`.`name`          as `symbol`,' +
            '`symbol_offsets`.`offset` as `offset`'  +
        'FROM' +
            '`symbol_offsets`,' +
            '`symbol_types`,'   +
            '`symbols`'         +
        'WHERE' +
            '`symbol_offsets`.`lib` = ? AND '                       +
            '`symbol_types`.`rowid` = `symbol_offsets`.`type` AND ' +
            '`symbols`.`rowid`      = `symbol_offsets`.`symbol`',
    (libid,))

    res = DB.fetchall()
    if not res:
        return None

    ret = []
    for row in res:
        ret.append({
            'id':      row[0],
            'type':    row[1],
            'symbol':  row[2],
            'address': row[3],
        })

    return ret


def get_gadgets(libid):

    DB.execute(
        'SELECT' +
            '`gadget_offsets`.`rowid`  as `id`,'     +
            '`gadget_types`.`name`     as `type`,'   +
            '`gadgets`.`name`          as `gadget`,' +
            '`gadget_offsets`.`offset` as `offset`,' +
            '`gadget_offsets`.`extra`  as `extra`'
        'FROM' +
            '`gadget_offsets`,' +
            '`gadget_types`,'   +
            '`gadgets`'         +
        'WHERE' +
            '`gadget_offsets`.`lib` = ? AND '                       +
            '`gadget_types`.`rowid` = `gadget_offsets`.`type` AND ' +
            '`gadgets`.`rowid`      = `gadget_offsets`.`gadget`',
    (libid,))

    res = DB.fetchall()
    if not res:
        return None

    ret = {}
    for row in res:

        if row[1] not in ret:
            ret[row[1]] = []

        dat = None if row[4] is None else json.loads(row[4])
        ret[row[1]].append({
            'id':          row[0],
            'gadget':      row[2],
            'address':     row[3],
            'constraints': dat
        })

    return ret


def get_packages(libid):

    DB.execute(
        'SELECT' +
            '`packages`.`rowid`  as `id`,'  +
            '`packages`.`name`   as `name`' +
        'FROM' +
            '`packages`' +
        'WHERE' +
            '`packages`.`lib` = ?',
    (libid,))

    res = DB.fetchall()
    if not res:
        return None

    ret = []
    for row in res:

        ret.append(row[1])

    return ret


def get_libs_by_file(file):

    sha1 = sha1_file(file)
    return get_libs_by_hash(sha1)


def get_libs_by_hash(digest):

    DB.execute(
        'SELECT' +
            '`rowid` as `id`,' +
            '`name`'           +
        'FROM'   +
            '`libs`' +
        'WHERE'  +
            '`md5`      = ? OR' +
            '`sha1`     = ? OR' +
            '`sha256`   = ? OR' +
            '`build_id` = ?',
    (digest, digest, digest, digest,))

    res = DB.fetchall()
    if not res:
        return None

    ret = []
    for row in res:
        ret.append(row[1])

    return ret


def get_libs_by_symbols(symbols):

    vals   = ()
    extra  = []

    archs  = []
    distro = ''

    if 'distro' in FILTER and FILTER['distro'] is not None:
        vals  += (FILTER['distro'],)
        distro = '`libs`.`distro` = ? AND '

    if 'arch' in FILTER and FILTER['arch'] is not None:
        for archid in FILTER['arch']:
            vals += (archid,)
            archs.append('`libs`.`arch` = ?')

    if len(archs) > 0:
        archs = ' OR '.join(archs)
        archs = '('+archs+') AND '
    else:
        archs = ''

    for symbol in symbols:
        vals  += (symbols[symbol], symbol,)
        extra.append('(`offset` & 0xfff = ? AND `symbols`.`name` = ?)')

    extra = ' OR '.join(extra)

    DB.execute(
        'SELECT' +
            '`libs`.`rowid`            as `id`,'     +
            '`libs`.`name`             as `lib`,'    +
            '`symbol_offsets`.`offset` as `offset`,' +
            '`symbols`.`name`          as `symbol`'  +
        'FROM'   +
            '`libs`,'           +
            '`symbol_offsets`,' +
            '`symbols`'         +
        'WHERE'  +
            distro+archs                                          +
            '`libs`.`rowid`    = `symbol_offsets`.`lib` AND'      +
            '`symbols`.`rowid` = `symbol_offsets`.`symbol` AND (' +
    extra+')', vals)

    res = DB.fetchall()
    if not res:
        return None

    counts = {}
    for row in res:
        name = row[1]
        if name not in counts:
            counts[name] = 0

        counts[name] += 1

    ret = []
    cnt = len(symbols)
    for name in counts:
        if counts[name] == cnt:
            ret.append(name)

    return sorted(ret, key=len)


def get_arch_ids(arch, endian=None):

    vals  = ()
    extra = []
    if arch is not None:
        vals += (arch, arch,)
        extra.append('(`display` = ? OR `name` = ?)')

    if endian is not None:
        vals += (endian,)
        extra.append('`endianess` = ?')

    extra = ' AND '.join(extra)

    DB.execute(
        'SELECT `rowid` as `id` FROM `archs` WHERE '+extra,
        vals
    )

    res = DB.fetchall()
    if not res:
        return None

    ret = []
    for row in res:
        ret.append(row[0])

    return ret if len(ret) > 0 else None


def get_distro_id(distro):

    DB.execute(
        'SELECT `rowid` as `id` FROM `distros` WHERE `name` = ?',
        (distro,)
    )

    res = DB.fetchone()
    if not res:
        return None

    return res[0]


def load_index():

    path  = os.path.realpath(os.path.dirname(__file__))
    path += '/db/libs.json'

    if not file_exists(path):
        return False

    with open(path, 'r') as file:
        obj = json.loads(file.read())

    if type(obj) is not dict:
        return False

    return obj


def get_types():

    libs = []
    data = load_index()
    if INDEX:
        for lib in INDEX:
            libs.append(lib)

    return libs


def get_cwd():

    return os.path.realpath(os.path.dirname(__file__))


def is_hex(val):

    return all(c in string.hexdigits for c in val)


def file_exists(file):

    return os.path.isfile(file)


def sha1_file(file):

    import hashlib

    sha1 = hashlib.sha1()
    with open(file, 'rb') as f:
        while True:
            chunk = f.read(0x10000)
            if not chunk:
                break

            sha1.update(chunk)

    return sha1.hexdigest()


def download(url, file=None):

    headers = {'Accept-Encoding': 'none'}
    if file is not None:

        with requests.get(url, stream=True, headers=headers) as req:
            with open(file, 'wb') as f:
                shutil.copyfileobj(req.raw, f)

        return file_exists(file)

    else:

        info('downloading: %s' % url)
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            return False

        return res.text

    return False


def update():

    global INDEX

    cwd = get_cwd()
    hst = 'raw.githubusercontent.com'
    url = 'https://'+hst+'/0xb0bb/karkinos/master/db/libs.json'

    if not download(url, cwd+'/db/libs.json'):
        error('cannot download index file from %s' % hst)
        return False

    INDEX = load_index()
    if not INDEX:
        error('cannot decode downloaded index file')
        return False

    for lib in INDEX:
        file = cwd+'/db/'+lib+'.db.xz'
        if not file_exists(file):

            url = 'https://'+hst+'/0xb0bb/karkinos/master/db/'+lib+'.db.xz'
            if not download(url, file):
                error('cannot download %s' % os.path.basename(file))
                return

        if not extract(file, INDEX[lib]['hash']):
            error('%s failed; mismatched hash' % os.path.basename(file))
            return False

        INDEX[lib]['time'] = time.time()

    with open(cwd+'/db/libs.json', 'w') as f:
        f.write(json.dumps(INDEX))

    check = version_check()
    if check is not None:
        print('Version %s is availible, your version is %s.' % (check[0], check[1]))
    else:
        print('Your version is up-to-date.')

    return True


def extract(file, hash):

    if not file_exists(file):
        return False

    info('extracting: %s' % file)

    out = file[:-3]
    cmd = 'xz -k -f -d {}'.format(shlex.quote(file))
    os.system(cmd)

    if not file_exists(out):
        return False

    return sha1_file(out) == hash


def connect(libdb):

    cwd  = get_cwd()
    path = cwd+'/db/%s.db' % libdb
    if not file_exists(path):
        return False

    global CONN, DB
    CONN = sqlite3.connect(path)
    DB   = CONN.cursor()

    if not CONN or not DB:
        return False

    return True


def dump(lib, symbols, with_gadgets=True):

    pad = ''
    if with_gadgets:
        pad = '  '
        print('\x1b[1mSymbols:\x1b[0m\n')

    for symbol in lib['symbols']:
        name = symbol['symbol']
        if name in symbols:
            print('%s%s = 0x%08x' %
                (pad, symbol['symbol'], symbol['address']))

    if ('gadgets' in lib and lib['gadgets'] is not None) and (with_gadgets or 'gadgets' in symbols):
        print('\n\x1b[1mGadgets:\x1b[0m\n')

        for category in lib['gadgets']:
            print('  \x1b[1m%s:\x1b[0m\n' % category)

            for gadget in lib['gadgets'][category]:

                if category == 'One Shot':

                    print('    \x1b[34;1m0x%08x:\x1b[0m %s' %
                        (gadget['address'], colour(gadget['gadget'], lib['arch'])))
                    if len(gadget['constraints']) > 0:
                        print('\n      \x1b[35;1mconstraints:\x1b[0m')
                        for constraint in gadget['constraints']:
                            print('        %s' % colour(constraint, lib['arch']))
                        print('')

                else:

                    print('    \x1b[34;1m0x%08x:\x1b[0m %s' %
                        (gadget['address'], colour(gadget['gadget'], lib['arch'])))

            print('')


def version_show():

    from karkinos import version

    print('Version: %s' % version.KARKINOS_VERSION)
    print('Author:  b0bb')
    print('Contact: https://twitter.com/0xb0bb')
    print('Project: https://github.com/0xb0bb/karkinos')


def version_check():

    from karkinos import version

    hst = 'raw.githubusercontent.com'
    url = 'https://'+hst+'/0xb0bb/karkinos/master/karkinos/version.py'
    dat = download(url)

    if not dat:
        return False

    major  = re.search('MAJOR_VERSION.+=.+(?P<value>[\d])', dat).group('value')
    minor  = re.search('MINOR_VERSION.+=.+(?P<value>[\d])', dat).group('value')

    remote = int('%s%s' % (major, minor))
    local  = int('%s%s' % (version.MAJOR_VERSION, version.MINOR_VERSION))

    if remote > local:
        return (
            '%s.%s' % (major, minor),
            '%s.%s' % (version.MAJOR_VERSION, version.MINOR_VERSION)
        )

    return None


def info(msg):

    print('%s' % msg)


def error(msg):

    print('\x1b[1;31merror:\x1b[0m %s' % msg)


def fatal(msg):

    error(msg)
    sys.exit(-1)


def colour(text, arch=None):

    regs = {
        'amd64': [
            'rax',  'rbx',  'rcx',  'rdx',
            'rdi',  'rsi',  'rbp',  'rsp',
            'r8',   'r9',   'r10',  'r11',
            'r12',  'r13',  'r14',  'r15',  'rip'
            'eax',  'ebx',  'ecx',  'edx',
            'edi',  'esi',  'ebp',  'esp',
            'r8d',  'r9d',  'r10d', 'r11d',
            'r12d', 'r13d', 'r14d', 'r15d', 'eip',
        ],

        'i386': [
            'eax',  'ebx',  'ecx',  'edx',
            'edi',  'esi',  'ebp',  'esp', 'eip',
        ],

        'arm': [
            'r0',  'r1', 'r2',  'r3',
            'r4',  'r5', 'r6',  'r7',
            'r8',  'r9', 'r10', 'r11',
            'r12', 'lr', 'sp',  'pc',
        ],

        'arm64': [
            'x0',  'x1',  'x2',  'x3',
            'x4',  'x5',  'x6',  'x7',
            'x8',  'x9',  'x10', 'x11',
            'x12', 'x13', 'x14', 'x15',
            'x16', 'x17', 'x18', 'x19',
            'x20', 'x21', 'x22', 'x23',
            'x24', 'x25', 'x26', 'x27',
            'x28', 'x29', 'x30', 'fp',
            'lr',  'ip0', 'ip1', 'pr',
            'sp',  'pc'
        ]
    }

    if arch in regs:
        match = '|'.join(regs[arch])
        text  = re.sub(r'('+match+')', r'REGSTART\1COLEND', text)
    
    text = re.sub(r'(0x[0-9a-f]+)', r'LITSTART\1COLEND', text)
    text = text.replace('REGSTART', '\x1b[33;1m')
    text = text.replace('LITSTART', '\x1b[32;1m')
    text = text.replace('COLEND', '\x1b[0m')
    return text


def main():

    global INDEX

    INDEX = load_index()
    if not INDEX:
        if not update():
            fatal('could not update database')

    for lib in INDEX:

        cwd  = get_cwd()
        file = cwd+'/db/'+lib+'.db'

        if not file_exists(file) or (int(INDEX[lib]['time']) + TIME) < time.time():
            update()
            break

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=DESC, epilog=EPILOG
    )

    parser.add_argument('--libdb', default='glibc', choices=get_types(),
                        help='the library database to use')

    parser.add_argument('--distro', default=None,
                        help='the linux distribution to filter in symbol search')

    parser.add_argument('--arch',   default='x86', choices=[
        'x86',   'amd64',   'i386',
        'arm',   'arm64',
        'mips',  'mips64',
        'ppc',   'ppc64',
        'sparc', 'sparc64',
        'm68k',  'hppa',    'sh4',
    ], help='architecture to filter in symbol search')

    parser.add_argument('--endian', default=None, choices=[
        'little', 'big',
    ], help='endianess to filter in symbol search')
    
    parser.add_argument('command', choices=[
        'find',
        'dump',
        'info',
        'update',
        'version',
    ], help='command to execute')

    parser.add_argument('args', nargs=argparse.REMAINDER,
                        help='arguments for specific command, see examples')

    args = parser.parse_args()
    if not connect(args.libdb):
        fatal('cannot connect to "%s"' % args.libdb)

    global FILTER
    FILTER['arch']   = get_arch_ids(args.arch, args.endian)
    FILTER['distro'] = get_distro_id(args.distro)

    if args.command == 'version':

        version_show()
        sys.exit(0)

    if args.command == 'find':

        if len(args.args) == 1:

            arg = args.args[0]
            if file_exists(arg):

                libs = get_libs_by_file(arg)
                if libs is None:
                    info('no results found')
                else:
                    for lib in libs:
                        print('name: %s' % lib)

            elif is_hex(arg):

                libs = get_libs_by_hash(arg)
                if libs is None:
                    info('no results found')
                else:
                    for lib in libs:
                        print('name: %s' % lib)

            else:
                fatal('argument not recognised')

        else:

            symbols = {}
            for i in range(0, len(args.args), 2):
                if i+1 >= len(args.args):
                    continue
                
                name = args.args[i]
                addr = args.args[i+1]

                if addr[:2] == '0x':
                    addr = addr[2:]

                if is_hex(addr):
                    addr = int(addr, 16)
                    addr = addr & 0xfff
                else:
                    fatal('invalid address provided for %s' % name)

                symbols[name] = addr
        
            if len(symbols) == 0:
                fatal('nothing to search for')

            libs = get_libs_by_symbols(symbols)
            if libs is None:
                info('no results found')
            else:
                for lib in libs:
                    print('name: %s' % lib)

    if args.command == 'dump':

        name = args.args[0]
        lib  = get_lib(name)
        if lib is None:
            info('no results found')
        else:

            gotargs = True
            symbols = args.args[1:]
            if len(symbols) == 0:
                gotargs = False
                symbols = [
                    '__libc_start_main_ret',
                    'system',
                    'dup2',
                    'read',
                    'write',
                    'str_bin_sh'
                ]

            dump(lib, symbols, not gotargs or 'gadgets' in symbols)

    if args.command == 'info':

        name = args.args[0]
        lib  = get_lib(name)
        if lib is None:
            info('no results found')
        else:

            print('Name:           %s' % name)
            print('Version:        %s (%s)' % (lib['version'], lib['variant']))
            print('Distribution:   %s' % lib['distro'])

            if lib['build_id']:
                print('Build ID:       %s' % lib['build_id'])

            print('\nFile Hashes:')
            print('    MD5:        %s' % lib['hash']['md5'])
            print('    SHA1:       %s' % lib['hash']['sha1'])

            if lib['packages']:
                print('\nPackages:')
                for package in lib['packages']:
                    print('                %s' % package)

    if args.command == 'update':

        if not update():
            fatal('could not update database')


if __name__ == '__main__':
    main()
