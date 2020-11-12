#!/usrbin/env python3

import logging
import socket
import struct
import subprocess
import os

DETACH = 0
ATTACH = 1
OK = 2

PORT = 10002

class RatelimitD:

    def __init__(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.bind(('0.0.0.0', PORT))
        self.soc.listen()


    def __attach(self, conn):
        uid = conn.recv(1024).decode().replace('-', '_')  # This is needed because in the filesystem dashes are replaced by underscores
        size = struct.unpack('<i', conn.recv(4))[0]

        f = open('file.o', 'wb') # Opening a new file for storing the bpf program sent by the client
        while size > 0:
            data = conn.recv(1024)
            f.write(data)
            size -= 1024
        f.close()

        try:
            pod_path = f'/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{uid}.slice'
            subprocess.check_call(['bpftool', 'prog', 'loadall', 'file.o', f'/sys/fs/bpf/{uid}', \
                'type', 'cgroup/skb']) # Loading with bpftool

            subprocess.check_call(['bpftool', 'cgroup', 'attach', pod_path, \
                'ingress', 'pinned', f'/sys/fs/bpf/{uid}/cgroup_skb_egress']) # Attaching to cgroup

        except subprocess.CalledProcessError:
            # logging.error('An error occurred while attaching the BPF program.')
            # conn.sendall(struct.pack('<i', ERROR))
            # self.state = ERROR
            # self.__detach()
            return

        logging.info('BPF program attached.')
        print('BPF program attached.')
        conn.sendall(struct.pack('<i', OK))


    def __detach(self, conn):
        uid = conn.recv(1024).decode().replace('-', '_')
        # subprocess.Popen(['bpftool', 'cgroup', 'detach', '/sys/fs/cgroup/user.slice/', \
        #        'egress', 'pinned', '/sys/fs/bpf/shaper/cgroup_skb_egress']).wait() # Removing from the kernel

        os.remove(f'/sys/fs/bpf/{uid}/cgroup_skb_egress')
        os.rmdir(f'/sys/fs/bpf/{uid}') # Remove from file system
        #logging.info('BPF program detached.')
        print('BPF program detached.')

        conn.sendall(struct.pack('<i', OK))


    def start(self):
        while True:
            try:
                conn, address = self.soc.accept()

                logging.info('Accepted connection from ' + address[0] + '.')

                cmd = struct.unpack('<i', conn.recv(4))[0]

                logging.info('Command ' + str(cmd) + ' from ' + address[0] + '.')

                if cmd == ATTACH:
                    conn.sendall(struct.pack('<i', OK))
                    self.__attach(conn )

                if cmd == DETACH:
                    self.__detach(conn)

            except KeyboardInterrupt:
                break

        conn.close()

def main():
    logging.basicConfig(filename='logfile.log', level=logging.DEBUG)
    daemon = RatelimitD()
    daemon.start()

if __name__ == '__main__':
    main()
