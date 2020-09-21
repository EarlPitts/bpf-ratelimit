#!/usrbin/env python3

import logging
import socket
import struct
from subprocess import Popen, PIPE
import os

DEBUG = 1

# States
READY = 0
BPF_ATTACHED = 1

# Responses
SUCCESS = 0
NO_PROG_ATT = 1

# Commands
ATTACH = 1
DETACH = 2

class RatelimitD:

    def __init__(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if DEBUG:
            self.soc.bind(('0.0.0.0', 10001))
        else:
            self.soc.bind(('0.0.0.0', 10000))

        self.state = READY
        self.soc.listen()

    def __attach(self):
        pass

    def __detach(self):
        pass

    def __send_response(self, resp_code):
        self.soc.send(struct.pack('<i', resp_code))



    def start(self):
        while True:
            try:
                soc, address = self.soc.accept()

                logging.info('Accepted connection from ' + address[0] + '.')

                cmd_pckd = soc.recv(4) # Receiving the package containing the command
                cmd = struct.unpack('<i', cmd_pckd)[0]

                logging.info('Command ' + str(cmd) + ' from ' + address[0] + '.')

                if cmd == ATTACH:

                    f = open('file.o', 'wb') # Opening a new file for storing the bpf program sent by the client
                    while True:
                        data = soc.recv(1024)
                        while data:
                            f.write(data)
                            data = soc.recv(1024)
                        f.close()
                        break

                    Popen(['bpftool', 'prog', 'loadall', 'file.o', '/sys/fs/bpf/shaper', 'type', 'cgroup/skb']).wait() # Loading with bpftool

                    Popen(['bpftool', 'cgroup', 'attach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Attaching to cgroup

                    logging.info('BPF program attached.')
                    self.status = BPF_ATTACHED
                    #self.__send_response(SUCCESS)


                if cmd == DETACH:
                    if self.status != BPF_ATTACHED:
                        self.__send_response(NO_PROG_ATT)
                        break

                    Popen(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Removing from the kernel
                    os.remove('/sys/fs/bpf/shaper/cgroup_skb_egress') # Remove from file system

                    logging.info('BPF program detached.')
                    #self.__send_response(SUCCESS)

            except KeyboardInterrupt:
                break

        soc.close()

def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)
    daemon = RatelimitD()
    daemon.start()

if __name__ == '__main__':
    main()
