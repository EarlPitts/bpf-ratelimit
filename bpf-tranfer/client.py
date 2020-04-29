import socket
import struct

DEBUG = 1

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(('localhost', 10001))

def get_response():
    resp = soc.recv(4)
    code = struct.unpack('I', resp)[0]
    return code

def menu():
    print('### Select an option ###\n')
    print('1. Attach BPF program')
    print('2. Detach BPF program\n')

    option = int(input("> "))

    return option

def main():
    option = menu()

    if option == 1: # Attaching
        print('Select a type: ') 
        print('1. cgroup/skb')

        bpf_type = int(input('> '))

        soc.send(struct.pack('I I', option, bpf_type))

        if DEBUG:
            filename = '../marker/marker.o'
        else:
            filename = input('File: ')

        file = open(filename, 'rb')

        while True:
            data = file.read(1024)
            soc.sendall(data)
            if not data:
                break
        file.close()

        # resp = get_response()

        # if resp == 0:
        #     print("Success.")
    
        soc.close()
    
    if option == 2: # Detaching

        soc.send(struct.pack('I I', option, 0))        

        resp = get_response()

        if resp == 0:
            print("Success.")
        elif resp == 1:
            print("Error, no bpf program attached.")

        soc.close()

main()
