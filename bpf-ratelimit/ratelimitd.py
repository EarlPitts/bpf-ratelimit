#!/usrbin/env python3

import socket
import struct
import os
import sys
from subprocess import Popen, PIPE
import shutil

DEBUG = 1

SUCCESS = 0
NO_PROG_ATT = 1

def send_response(resp_code):
    soc.send(struct.pack('I', resp_code))


def get_tag(): # Getting the tag for the running bfp program
    p = Popen(['bpftool', 'prog', 'list'], stdout=PIPE)
    resp = p.communicate()[0].decode('ascii').split('\n')
    tag = ''

    for line in resp:
        # print(line)
        if 'name' in line:
            i = 0
            splitten = line.split()
            for word in splitten:
                if word == 'tag':
                    break
                i += 1
            tag = splitten[i+1]

    return tag


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if DEBUG:
    #server.bind(('localhost', 10001))
    ipv4 = os.popen('ip addr show ens3').read().split("inet ")[1].split("/")[0]
    server.bind((ipv4, 10001))
else:
    ipv4 = os.popen('ip addr show ens3').read().split("inet ")[1].split("/")[0]
    server.bind((ipv4, 10000))

server.listen()

while True:
    try:
        soc, address = server.accept()

        print(address)

        cmd_pckd = soc.recv(8) # Receiving the package containing the command
        cmd = struct.unpack('I I', cmd_pckd)
        option = cmd[0]
        bpf_type = cmd[1]

        if DEBUG:
            print(option)
            print(bpf_type)


        if option == 1: # Attaching a new bpf program

            f = open('file.o', 'wb') # Opening a new file for storing the bpf program sent by the client
            while True:
                data = soc.recv(1024)
                while data:
                    f.write(data)
                    data = soc.recv(1024)
                f.close()
                #soc.close()
                break

            if bpf_type == 1:
                Popen(['bpftool', 'prog', 'loadall', 'file.o', '/sys/fs/bpf/marker', 'type', 'cgroup/skb']) # Loading with bpftool

                tag = get_tag() # Getting the tag for the newly attached program

                if DEBUG:
                    print(tag)

                Popen(['bpftool', 'cgroup', 'attach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'tag', tag]) # Attaching to cgroup

                #send_response(SUCCESS)


        if option == 2: # Detaching a bpf program
            tag = get_tag()

            if DEBUG:
                print(tag)

            if tag != '':
                Popen(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'tag', tag]) # Removing from the kernel
                shutil.rmtree('/sys/fs/bpf/marker') # Remove from file system

                send_response(SUCCESS)
            else:
                send_response(NO_PROG_ATT)
                print('No program attached!')

        soc.close()



    except KeyboardInterrupt:
        break

server.close()
