from kubernetes import client, config, watch

import argparse
import logging
import os
import socket
import struct

from bpf_generator import BPFGenerator

pods = []

DETACH = 0
ATTACH = 1
OK = 2

PORT = 10002

def connect(host, port=10002):
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((host, port))
        logging.info('Connection to ' + host + ' has been established.')
        return soc
    except ConnectionRefusedError:
        logging.error('Establishing connection to host ' + host
                      + ' on port ' + str(port) + ' has failed.')

        return


def attach_shaper(name, host_ip, uid, rate):
    soc = connect(host_ip)
    rate = rate * 125000
    BPFGenerator.generate(rate)

    soc.sendall(struct.pack('<i', ATTACH))

    resp = struct.unpack('<i', soc.recv(4))[0]

    if resp == OK:
        try:
            size = os.path.getsize('shaper.o')
            soc.sendall(bytes(uid, encoding='UTF-8'))
            __check_resp(soc)
            soc.sendall(struct.pack('<i', size))
            __check_resp(soc)

            with open('shaper.o', 'rb') as f:
                while True:
                    data = f.read(1024)
                    soc.sendall(data)
                    if not data:
                        break
        except ConnectionError:
            print("Error")
            # TODO Handle exception

    print('BPF Program sent to remote machine.')

    os.remove('shaper.o')

    resp = struct.unpack('<i', soc.recv(4))[0]
    if resp == OK:
        pods.append(uid)
        print('BPF Program attached successfully.')
    else:
        print('An error occurred while attaching the program. Try again.')

    soc.close()


def detach_shaper(host_ip, uid):
    soc = connect(host_ip)

    soc.sendall(struct.pack('<i', DETACH))

    resp = struct.unpack('<i', soc.recv(4))[0]

    if resp == OK:
        soc.sendall(bytes(uid, encoding='UTF-8'))
    else:
        print('Cannot detach.') # TODO Currently this is not functioning

    resp = struct.unpack('<i', soc.recv(4))[0]
    if resp == OK:
        print('BPF Program detached successfully.')
        pods.remove(uid)
    else:
        print('An error occurred while detaching the program.')

    soc.close()

def __check_resp(soc):
    resp = struct.unpack('<i', soc.recv(4))[0]
    if resp == OK:
        return
    else:
        raise ConnectionError

def main():
    config.load_kube_config()

    v1 = client.CoreV1Api()
    w = watch.Watch()

    for event in w.stream(v1.list_pod_for_all_namespaces):
        if event['object'].kind != 'Pod':
            continue

        try:
            rate = int(event['object'].metadata.labels['rate'].rstrip('M'))
        except KeyError:
            continue

        name = event['object'].metadata.name
        event_type = event['type']
        host_ip = event['object'].status.host_ip
        phase = event['object'].status.phase
        uid = event['object'].metadata.uid

        if event_type == 'DELETED':
            print(f'{name}, {host_ip}, {event_type}, {uid}, {rate}')
            detach_shaper(host_ip, uid)

        if event_type == 'MODIFIED' and host_ip:
            if uid not in pods:
                print(f'{name}, {host_ip}, {event_type}, {uid}, {rate}')
                attach_shaper(name, host_ip, uid, rate)


if __name__ == '__main__':
    main()
