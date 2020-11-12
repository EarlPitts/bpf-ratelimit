# BPF-ratelimit

BPF-ratelimit is a tool that lets you limit the bandwidth of pods in a kubernetes cluster.
It's watching the pod creation a deletion events in the background, and applies the specified limit automatically.
The limit can be specified in the pod yaml file.

## Example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example_pod
  labels: 
    component: web
    rate: "1M" # You can specify the limit like this
spec:
  containers:
    - name: sise2
      image: dashsaurabh/progressive-coder
      image: quay.io/openshiftlabs/simpleservice:0.5.0
      ports: 
      - containerPort: 9875
```


## Prerequisites

You need [bpftool](https://lwn.net/Articles/739357/) and Python 3 installed on each node.
And you also need clang on the master node.
