import argparse
import logging
import os
import socket
import struct

from bpf_generator import BPFGenerator

# Commands
ATTACH = 1
DETACH = 2
STATUS = 3

# Rsponses
SUCCESS = 4
NO_PROG_ATT = 5
ERROR = 6

# States
READY = 7
BPF_ATTACHED = 8

def connect(host='localhost', port='10001'):
    host = 'localhost'
    port = 10001
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((host, port))
        logging.info('Connection to ' + host + ' has been established.')
        return soc
    except ConnectionRefusedError:
        logging.error('Establishing connection to host ' + host
                      + ' on port ' + str(port) + ' has failed.')
        return


def attach_shaper(conn, limit):

    BPFGenerator.generate(limit)

    size = os.path.getsize('shaper.o')

    s = struct.pack('<i i', ATTACH, size)

    conn.sendall(s)

    with open('shaper.o', 'rb') as f:
        while True:
            data = f.read(1024)
            conn.sendall(data)
            if not data:
                break

    logging.info('BPF Program sent to remote machine.')

    os.remove('shaper.o')

    resp = struct.unpack('<i', conn.recv(4))[0]
    if resp == SUCCESS:
        logging.info('BPF Program attached successfully.')
        print('BPF Program attached successfully.')
    else:
        print('An error occurred while attaching the program. Try again.')

def detach_shaper(conn):

    s = struct.pack('<i i', DETACH, 0) # The 0 is just a filler here
    conn.sendall(s)

    resp = struct.unpack('<i', conn.recv(4))[0]
    if resp == SUCCESS:
        logging.info('BPF Program detached successfully.')
        print('BPF Program detached successfully.')
    elif resp == NO_PROG_ATT:
        logging.info('No BPF Program attached on target!')
        print('No BPF Program attached on target!')
    else:
        print('An error occurred while attaching the program.')


    conn.close()


def get_status(conn):
    conn.sendall(struct.pack('<i i', STATUS, 0)) # 0 is a filler value
    state = struct.unpack('<i', conn.recv(4))[0]

    if state == READY or state == NO_PROG_ATT:
        print('Target has no program attached.')
    elif state == BPF_ATTACHED:
        print('There is a BPF program currently attached to target.')
    else:
        print('There were some prolems in the last operation. Try again.')

def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)

    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--attach', action='store_true', help='Attach ratelimiter.')
    parser.add_argument('-d', '--detach', action='store_true', help='Detach ratelimiter.')
    parser.add_argument('-s', '--status', action='store_true', help='Query target for it\'s status.')
    parser.add_argument('-l', '--limit', action='store', dest='limit',
                    help='Set the limit in bytes/sec')
    parser.add_argument('-t', '--target', action='store', help='Target machine IP.')
    parser.add_argument('-p', '--port', action='store', help='Target machine port.')

    args = parser.parse_args()

    conn = connect(args.target, args.port)

    if args.attach:
        if args.limit:
            attach_shaper(conn, args.limit)
        else:
            attach_shaper(conn, 1250000)

    elif args.detach:
        detach_shaper(conn)

    elif args.status:
        get_status(conn)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
