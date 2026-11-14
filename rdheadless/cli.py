"""Command-line utilities for the independent RustDesk headless application."""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from pathlib import Path
import secrets
import sys

from .client import Peer


def _client_id() -> str:
    root=Path.home()/'.config'/'rdheadless'
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    location=root/'client-id'
    try:
        descriptor=os.open(str(location),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except FileNotFoundError:
        ident='cli-'+secrets.token_hex(16)
        descriptor=os.open(str(location),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(descriptor,'w') as f:
            f.write(ident+'\n')
        return ident
    with os.fdopen(descriptor,'r') as f:
        return f.read(128).strip()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == '--worker':
        if sys.platform != 'linux' or len(argv) != 2:
            raise SystemExit('Worker execution requires Linux and a socket descriptor')
        from .worker import run_worker
        run_worker(int(argv[1]))
        return 0
    if argv and argv[0] == '--exec-shell':
        if sys.platform != 'linux' or len(argv) != 3:
            raise SystemExit('Shell execution requires Linux')
        from .exec_shell import exec_shell
        exec_shell(argv[1], argv[2])
        return 0
    parser=argparse.ArgumentParser(prog='rdheadless')
    sub=parser.add_subparsers(dest='service',required=True)
    host=sub.add_parser('host',help='run the headless RustDesk host')
    host.add_argument('--config',required=True)
    identity=sub.add_parser('identity',help='display the server public identity')
    identity.add_argument('--config',required=True)
    connect=sub.add_parser('client',help='connect to a headless RustDesk host')
    connect.add_argument('address',help='host:port, e.g. 127.0.0.1:21118')
    connect.add_argument('--peer-id',required=True)
    connect.add_argument('--peer-key',required=True,help='pinned server Ed25519 public key (base64)')
    connect.add_argument('--mode',choices=['private','public'],required=True)
    connect.add_argument('--via-hbbs',action='store_true',
                         help='connect by RustDesk ID using hbbs and hbbr relay servers')
    connect.add_argument('--relay',default='',
                         help='hbbr hostname:port when --via-hbbs is used')
    connect.add_argument('--rendezvous-key',default='',
                         help='hbbr licence key when the relay requires one')
    connect.add_argument('--client-id',default='')
    connect.add_argument('--ask-connection-password',action='store_true',
                         help='prompt for an additional static RustDesk connection password')
    commands=connect.add_subparsers(dest='command',required=True)
    commands.add_parser('terminal',help='interactive remote PTY')
    ls=commands.add_parser('ls',help='list remote directory')
    ls.add_argument('path',nargs='?',default='')
    get=commands.add_parser('get',help='download a regular file')
    get.add_argument('remote')
    get.add_argument('local')
    put=commands.add_parser('put',help='upload a regular file')
    put.add_argument('local')
    put.add_argument('remote_directory')
    opts=parser.parse_args(argv)
    if opts.service=='host':
        if sys.platform != 'linux':
            parser.error('the host service requires Linux')
        from .server import serve
        serve(opts.config)
        return 0
    if opts.service=='identity':
        if sys.platform != 'linux':
            parser.error('host identity management requires Linux')
        from .server import Config, HostServer
        config=Config.from_file(opts.config)
        data=HostServer(config).identity
        print('ID:',data.device_id)
        print('Public key (base64):',base64.b64encode(data.public).decode())
        return 0
    if opts.address.count(':')!=1:
        parser.error('address must be a host:port pair; use an IPv4 address or DNS name')
    hostname,port=opts.address.rsplit(':',1)
    try: key=base64.b64decode(opts.peer_key,validate=True)
    except ValueError: parser.error('invalid base64 server public key')
    kind='terminal' if opts.command=='terminal' else 'file'
    username=''
    if opts.mode=='public':
        username=input('Linux user: ').strip()
        password=getpass.getpass('PAM password: ')
    else:
        password=getpass.getpass('RustDesk connection password: ')
    connection_password=(getpass.getpass('RustDesk connection password: ')
                         if opts.mode=='public' and opts.ask_connection_password else '')
    client_id=opts.client_id or _client_id()
    relay_sock = None
    if opts.via_hbbs:
        from .rendezvous import connect_via_relay, server_address
        from . import protocol as p
        if not opts.relay:
            parser.error('--via-hbbs requires --relay for the destination hbbr server')
        relay_sock = connect_via_relay(opts.address, opts.relay, opts.peer_id,
            {'terminal': p.TERMINAL_CONN, 'file': p.FILE_TRANSFER_CONN,
             'port': p.PORT_FORWARD_CONN}[kind], opts.rendezvous_key)
    try:
        peer=Peer.connect((hostname,int(port)),opts.peer_id,key,opts.mode,kind,
                          password,username,client_id,connection_password=connection_password,
                          connected_socket=relay_sock)
    except BaseException:
        if relay_sock is not None:
            relay_sock.close()
        raise
    try:
        if opts.command=='terminal':
            return int(peer.terminal())
        if opts.command=='ls':
            for name,kind,size in peer.ls(opts.path):
                print(f'{"dir " if kind==0 else "file"} {size:>12}  {name}')
        if opts.command=='get':
            peer.get_file(opts.remote,opts.local)
        if opts.command=='put':
            peer.put_file(opts.local,opts.remote_directory)
        return 0
    finally:
        peer.close()
