import argparse
import logging
import socket
import struct

from bpf_generator import BPFGenerator

DEBUG = 1

# Commands
ATTACH = 1
DETACH = 2

# Rsponses
SUCCESS = 0
NO_PROG_ATT = 1

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


def attach_shaper(soc, limit):

    s = struct.pack('<i', ATTACH)

    soc.sendall(s)

    BPFGenerator.generate(limit)

    with open('shaper.o', 'rb') as f:
        while True:
            data = f.read(1024)
            soc.sendall(data)
            if not data:
                break

    logging.info('BPF Program sent to remote machine.')

    # resp = struct.unpack('<i', soc.recv(4))[0]
    # if resp == SUCCESS:
    #     logging.info('BPF Program attached successfully.')
    #     print('BPF Program detached successfully.')
    # else:
    #     print('An error occurred on the target.')

def detach_shaper(soc):

    s = struct.pack('<i', DETACH)
    soc.sendall(s)

    # resp = struct.unpack('<i', soc.recv(4))[0]
    # if resp == SUCCESS:
    #     logging.info('BPF Program detached successfully.')
    #     print('BPF Program detached successfully.')
    # elif resp == NO_PROG_ATT:
    #     logging.info('No BPF Program attached on target!')
    #     print('No BPF Program attached on target!')



def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)

    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--attach', action='store_true', help='Attach ratelimiter.')
    parser.add_argument('-d', '--detach', action='store_true', help='Detach ratelimiter.')
    parser.add_argument('-l', '--limit', action='store', dest='limit',
                    help='Set the limit in bytes/sec')
    parser.add_argument('-t', '--target', action='store', help='Target machine IP.')
    parser.add_argument('-p', '--port', action='store', help='Target machine port.')

    args = parser.parse_args()

    soc = connect(args.target, args.port)

    if args.attach:
        if args.limit:
            attach_shaper(soc, args.limit)
        else:
            attach_shaper(soc, 1250000)

    elif args.detach:
        detach_shaper(soc)

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
