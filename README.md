


# 基本介绍


tap-rs 是一个使用Rust语言编写的Linux下的基于macvtap的二层包转发程序
它可以将多个本地的虚拟网卡流量完全映射到多个远端的网卡上，既本地和远端有完全一样的网卡，有着同样的ip和mac地址，访问本地如同访问远端。


## 优势

- 非常特殊的网卡映射功能 （任意发挥想象力）
- 极低的内存占用 (小于 10MB)
- 非常小的体积 (最低可以小于500k)
- 可以使用musl纯静态编译
- 基于Rust的async udp通信


## build

```bash

cargo build --release

```

## 基础使用

```bash


tap-rs -c client.toml


```



## 运行环境

当前在ubuntu18.04测试通过


## 系统基础配置

```bash

sysctl -w net.ipv4.ip_forward=1

#For receiving ARP replies:
sysctl -w net.ipv4.conf.all.arp_filter=1
sysctl -w net.ipv4.conf.default.arp_filter=1


#For sending ARP:

sysctl -w net.ipv4.conf.all.arp_announce=2
sysctl -w net.ipv4.conf.default.arp_announce=2


```


## 客户端配置

完整配置选项请看src/config.rs

```toml

#is_daemon = true #可选 是否守护进程，默认false
tap_mode = "macvtap" #tap or macvtap   macvtap模式必须先创建好网卡p和mac然后在启动监听，tap模式可以运行是创建，然后在外部配置ip和mac
run_mode = "client"
#mtu = 1500  #可选 默认为1500

[server]
bind_addr = "192.168.1.100:1234" #服务器ip地址+端口

[[nics]]
ifname = "tap0"
ip = "18.8.80.150"
mac =  "be:17:dd:5c:07:17"

[[nics]]
ifname = "tap1"
ip = "18.8.80.151"
mac = "5e:56:56:13:23:a4"

# 客户端假如接受服务端的远程配置下发，来覆盖本地配置，这个时候nics的配置可以随便写，但必须最少有一组来占位
#use_remote_config=true


```


## 服务端配置

```toml

#is_daemon = true 是否守护进程，默认false
tap_mode = "tap" #tap or macvtap
run_mode = "server"
#client_tap_mode = "macvtap" #tap or macvtap，使用远程下发的时候客户端运行的tap模式，这个会覆盖客户端原有的配置

[server]
bind_addr = "192.168.1.100:1234" #服务器ip地址+端口
#script_path = "/tmp/tap_client.sh" #假如使用服务器下发配置模式，这个脚本将先在客户端上执行，然后根据server下发配置启动tap监听。假如脚本执行返回不等于0，客户端出错退出。 

[[nics]]
ifname = "tap0"  #网卡名
ip = "18.8.80.150"  # 网卡绑定ip地址，事前或者事先从外部绑定好。client和server要一致
mac =  "be:17:dd:5c:07:17" # 网卡的mac地址，事前或者事后从外部绑定好。client和server要一致

[[nics]]
ifname = "tap1"
ip = "18.8.80.151"
mac = "5e:56:56:13:23:a4"


```


## 创建macvtap网卡例子



```bash

modprobe macvtap

ip link add link ens192 name tap0 type macvtap mode bridge
ip link add link ens192 name tap1 type macvtap mode bridge


```


## 网络配置


在多虚拟网卡且网卡ip网段相同的情况下，client和server上都需要配置策略路由才能工作。


例子如下:


``` bash
cp rt_tables /etc/iproute2/


ifconfig tap0 up
ifconfig tap1 up


ip addr add 18.8.80.150/24 dev tap0
ip addr add 18.8.80.151/24 dev tap1

ip link set tap0 address be:17:dd:5c:07:17
ip link set tap1 address 5e:56:56:13:23:a4


ip route add 18.8.80.0/24 dev tap0 src 18.8.80.150 table 150
ip route add 18.8.80.0/24 dev tap1 src 18.8.80.151 table 151


ip route add default dev tap0 via 18.8.80.1 table 150
ip route add default dev tap1 via 18.8.80.1 table 151

ip rule add from 18.8.80.150 table 150
ip rule add from 18.8.80.151 table 151

```


## 注意事项


1. 不借助特殊手段，client可以是macvtap或者tap+网桥（最好是macvtap），但服务器端最好是tap（这个组合测试通过）。
2. 注意：客户端和服务器端虚拟网卡ip和mac地址必须完全相同。
3. 多虚拟网卡且同网段的情况下必须配置策略路由。


