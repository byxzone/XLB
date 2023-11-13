# XLB - XDP Load Balancer

based on (XDP Tutorial - Basic04)

## Usage

Setup dependencies (taking ubuntu23.10 (kernel v6.5) as an example)

```
sudo apt update
sudo apt install clang llvm libelf-dev libpcap-dev build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic libc6-dev-i386
```

Compile the project

```
make
```

after you run this command, the xdp program is attached to your NIC DEVICE receive queue

```
sudo ./xdp_loader -d **YOUR_DEV_NAME**
```

use this program to pin BPF_MAP to sysfs and initialize map data used in kernel practical

```
sudo ./xlb_map -d **YOUR_DEV_NAME**
```

before test the load balancer, you need to setup dr mode network, see this file: [drconfig.md](./drconfig.md)

then, you can try the xlb, for example

```
curl 192.168.122.101
```

you will get a return from vm_1, and you can check the BPF_MAP info in /sys/fs/bpf/**YOUR_DEV_NAME**

```
sudo cat /sys/fs/bpf/**YOUR_DEV_NAME**/servs_map_ipv4
sudo cat /sys/fs/bpf/**YOUR_DEV_NAME**/conn_hash_map
sudo cat /sys/fs/bpf/**YOUR_DEV_NAME**/rs_info_map
...
```

and you also see the rate of XDP_PASS/XDP_TX/...

```
sudo ./xdp_stats -d **YOUR_DEV_NAME**
```

result:

```
Collecting stats from BPF map
 - BPF map (bpf_map_type:6) id:1720 name:xdp_stats_map key_size:4 value_size:16 max_entries:5
XDP-action  
XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250293
XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250259
XDP_PASS            1293 pkts (        20 pps)         144 Kbytes (     0 Mbits/s) period:0.250261
XDP_TX                 0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250263
XDP_REDIRECT           0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250265
```



