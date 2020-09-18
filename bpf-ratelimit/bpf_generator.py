import subprocess
import os

class BPFGenerator:

    @staticmethod
    def generate(speed):
        """ Generates the BPF program with the given speed (in bytes/sec). """

        bpf_program = f"""
            #include <linux/bpf.h>
            #include "bpf_helpers.h"

            #define bpf_printk(fmt, ...)                        \\
            ({{                                                 \\
                    char ____fmt[] = fmt;                       \\
                    bpf_trace_printk(____fmt, sizeof(____fmt),  \\
                                    ##__VA_ARGS__);             \\
            }})

            #define DROP_PKT        0
            #define ALLOW_PKT       1

            static __s64 tokens = {speed};
            static __u64 time = 0;
            static const __u32 bps = {speed}; //speed in bytes/sec (10Mbps now)
            static const __u32 extra_tokens = bps >> 9; //few extra tokens for smoother operation

            SEC("cgroup_skb/egress")
            int pkt_tbf(struct __sk_buff *skb)
            {{
                    __u64 now = bpf_ktime_get_ns();
                    __u64 new_tokens = (bps * (now - time)) / 1000000000;
                    tokens += (new_tokens + extra_tokens);
                    tokens -= skb->len;
                    time = now;
                    if(tokens > bps)
                            tokens = bps;
                    if(tokens < 0)
                    {{
                            //bpf_printk("Drop pkt: %d\\n", tokens);
                            tokens = 0;
                            return DROP_PKT;
                    }}

                    //bpf_printk("Allow, tokens: %lld\\n", tokens);
                    return ALLOW_PKT;
            }}

            char _license[] SEC("license") = "GPL";
            """

        with open('shaper.c', 'w') as f:
            f.write(bpf_program)

        subprocess.Popen(['clang', '-target', 'bpf', '-c', '-O2', 'shaper.c', '-o', 'shaper.o', '-I/usr/include/x86_64-linux-gnu']).wait()

        os.remove('shaper.c')
