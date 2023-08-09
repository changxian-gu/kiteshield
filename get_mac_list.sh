#!/bin/sh

# 获取/sys/class/net目录下的所有目录（即网卡）
network_interfaces=$(ls /sys/class/net)

# 遍历每个网卡
for interface in $network_interfaces; do
    # 提取网卡名称
    interface_name=$interface
    # 提取网卡的MAC地址
    mac_address=$(cat "/sys/class/net/$interface/address")
    # 打印网卡名称和MAC地址
    echo "$interface_name"
    echo "$mac_address"
done

