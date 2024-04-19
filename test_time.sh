#!/bin/bash

# 异常情况下退出脚本
set -e

# 检查程序名是否已传入
if [ "$#" -ne 1 ]; then
    echo "使用方法: $0 程序名"
    exit 1
fi

program_name=$1
total_time=0

# 执行程序，计算总时间
for i in $(seq 1 10); do
    # 时间统计
    start_time=$(date +%s%N)  # 获取纳秒时间戳
    $program_name  # 这里执行您的程序，保证其输出
    end_time=$(date +%s%N)  # 结束时间
    duration=$((end_time - start_time))  # 计算持续时间
    total_time=$((total_time + duration))  # 累加总时间
done

# 计算平均时间并转换为秒
average_time_ns=$((total_time / 10))  # 计算平均时间（纳秒）
average_time=$(echo "scale=3; $average_time_ns / 1000000000" | bc)  # 转换为秒

echo "平均运行时间：$average_time 秒"
