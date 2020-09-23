#!/usrbin/env python3

import logging
import socket
import struct
import subprocess
import os

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

class RatelimitD:

    def __init__(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.bind(('0.0.0.0', 10001))

        self.state = READY
        self.soc.listen()


    def __repair(self):
        """ Tries to automatically correct the problem. """
        try:
            subprocess.check_call(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/unified/user.slice/', \
               'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress'])
        except subprocess.CalledProcessError:
            logging.info('Repair: BPF program seems to be detached.')

        try:
            os.remove('/sys/fs/bpf/shaper/cgroup_skb_egress') # Remove from file system
        except FileNotFoundError:
            logging.info('Repair: BPF program is already deleted from the filesystem.')

        self.state = NO_PROG_ATT


    def __attach(self, conn, size):
        f = open('file.o', 'wb') # Opening a new file for storing the bpf program sent by the client
        while size > 0:
            data = conn.recv(1024)
            f.write(data)
            size -= 1024
        f.close()

        try:
            subprocess.check_call(['bpftool', 'prog', 'loadall', 'file.o', '/sys/fs/bpf/shaper', \
                'type', 'cgroup/skb']) # Loading with bpftool

            subprocess.check_call(['bpftool', 'cgroup', 'attach', '/sys/fs/cgroup/unified/user.slice/', \
                'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']) # Attaching to cgroup

        except subprocess.CalledProcessError:
            logging.error('An error occurred while attaching the BPF program.')
            conn.sendall(struct.pack('<i', ERROR))
            self.state = ERROR
            self.__repair()
            return

        logging.info('BPF program attached.')
        self.state = BPF_ATTACHED
        conn.sendall(struct.pack('<i', SUCCESS))


    def __detach(self, conn):
        if self.state != BPF_ATTACHED:
            conn.sendall(struct.pack('<i', NO_PROG_ATT))
            return

        subprocess.Popen(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/unified/user.slice/', \
               'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Removing from the kernel

        os.remove('/sys/fs/bpf/shaper/cgroup_skb_egress') # Remove from file system
        logging.info('BPF program detached.')
        self.state = NO_PROG_ATT
        conn.sendall(struct.pack('<i', SUCCESS))


    def __send_state(self, conn):
        breakpoint()
        conn.sendall(struct.pack('<i', self.state))

    def start(self):
        while True:
            try:
                conn, address = self.soc.accept()

                logging.info('Accepted connection from ' + address[0] + '.')

                cmd = struct.unpack('<i i', conn.recv(8))

                logging.info('Command ' + str(cmd) + ' from ' + address[0] + '.')

                if cmd[0] == ATTACH:
                    self.__attach(conn, cmd[1])

                if cmd[0] == DETACH:
                    self.__detach(conn)

                if cmd[0] == STATUS:
                    self.__send_state(conn)

            except KeyboardInterrupt:
                break

        conn.close()

def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)
    daemon = RatelimitD()
    daemon.start()

if __name__ == '__main__':
    main()
