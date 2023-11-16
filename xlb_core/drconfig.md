以 VIP `192.168.122.101` 网卡名称为 `enp1s0` 为例

- LB

```
ifconfig enp1s0:0 192.168.122.101 netmask 255.255.255.255
```

- RS

将对应网卡设置为只回应目标IP为自身接口地址的ARP请求

```
echo "1" > /proc/sys/net/ipv4/conf/lo/arp_ignore
echo "1" > /proc/sys/net/ipv4/conf/all/arp_ignore
```

将ARP请求的源IP设置为enp1s0上的IP，也就是RIP

```
echo "2" > /proc/sys/net/ipv4/conf/lo/arp_announce
echo "2" > /proc/sys/net/ipv4/conf/all/arp_announce
```

添加IP地址为VIP的虚拟网卡lo:0

```
ifconfig lo:0 192.168.122.101 broadcast 192.168.122.101 netmask 255.255.255.255
```

配置路由

```
route add -host 192.168.122.101 dev lo:0
```

