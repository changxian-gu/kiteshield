#!/bin/bash

# 起始时间
start_time=$(date +%s%N)

# 在子Shell中启动GIMP并获取它的PID
( gimp & echo $! >&3 ) 3>gimppid.txt &
GIMP_PID=$(cat gimppid.txt)

# 等待GIMP界面出现
while true; do
    if xdotool search --name "GNU Image Manipulation Program"; then
        break
    fi
    sleep 0.01
done

# 结束时间
end_time=$(date +%s%N)

# 计算差值并转换为秒
elapsed_time=$(echo "scale=3; ($end_time - $start_time) / 1000000000" | bc)

echo "GIMP加载时间: $elapsed_time 秒"

# 关闭GIMP
kill $GIMP_PID
