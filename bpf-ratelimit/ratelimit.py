import argparse
import logging
import socket
import struct

from bpf_generator import BPFGenerator

DEBUG = 1

def attach_shaper(limit):
    host = 'localhost'
    port = 10001
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((host, port))
        logging.info('Connection to ' + host + ' has been established.')
    except ConnectionRefusedError:
        logging.error('Establishing connection to host ' + host
                      + ' on port ' + str(port) + ' has failed.')
        return

    BPFGenerator.generate(limit)

    with open('shaper.o', 'rb') as f:
        breakpoint()
        while True:
            data = f.read(1024)
            soc.sendall(data)
            if not data:
                break

    logging.info('BPF Program sent to remote machine.)



def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)

    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--attach', action='store_true', help='Attach ratelimiter.')
    parser.add_argument('-d', '--detach', action='store_true', help='Detach ratelimiter.')
    parser.add_argument('-l', '--limit', action='store', dest='limit',
                    help='Set the limit in bytes/sec')

    args = parser.parse_args()

    if args.attach:
        if args.limit:
            attach_shaper(args.limit)
        else:
            attach_shaper(1250000)

    elif args.detach:
        pass

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
