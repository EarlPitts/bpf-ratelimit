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


    def start(self):
        while True:
            try:
                conn, address = self.soc.accept()

                logging.info('Accepted connection from ' + address[0] + '.')

                cmd = struct.unpack('<i i', conn.recv(8))

                logging.info('Command ' + str(cmd) + ' from ' + address[0] + '.')

                if cmd[0] == ATTACH:

                    size = cmd[1]
                    f = open('file.o', 'wb') # Opening a new file for storing the bpf program sent by the client
                    while size > 0:
                        data = conn.recv(1024)
                        f.write(data)
                        size -= 1024
                    f.close()

                    Popen(['bpftool', 'prog', 'loadall', 'file.o', '/sys/fs/bpf/shaper', 'type', 'cgroup/skb']).wait() # Loading with bpftool

                    Popen(['bpftool', 'cgroup', 'attach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Attaching to cgroup

                    logging.info('BPF program attached.')
                    self.status = BPF_ATTACHED
                    conn.sendall(struct.pack('<i', SUCCESS))


                if cmd[0] == DETACH:
                    if self.status != BPF_ATTACHED:
                        conn.sendall(struct.pack('<i', NO_PROG_ATT))
                        break

                    Popen(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/unified/user.slice/', 'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Removing from the kernel
                    os.remove('/sys/fs/bpf/shaper/cgroup_skb_egress') # Remove from file system
                    logging.info('BPF program detached.')
                    conn.sendall(struct.pack('<i', SUCCESS))

            except KeyboardInterrupt:
                break

        conn.close()

def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)
    daemon = RatelimitD()
    daemon.start()

if __name__ == '__main__':
    main()
