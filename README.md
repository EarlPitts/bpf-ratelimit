# BPF-ratelimit

A simple tool for limiting network rate of target machine with BPF.

## Prerequisites

You need [bpftool](https://lwn.net/Articles/739357/) and Python 3 installed on both machines.  
And you also need clang on the client side.

1. Copy the _server.py_ script to the target machine.
2. Run it.
3. Use the client.py script to transfer the program to the target. (`--help` for available options)
