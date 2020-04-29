# BPF-transer

A simple tool for transferring BPF programs to a target machine.

## Prerequisites

The target computer must have [bpftool](https://lwn.net/Articles/739357/) and python 3installed.

1. Copy the *server.py* script to the target machine.
2. Run it.
3. Compile the BPF program you want to transfer. (The target and the machine you are compiling on should have the same kernel.)
4. Use the client.py script to transfer the program to the target.
