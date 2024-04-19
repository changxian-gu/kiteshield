#!/bin/bash

# 前两个固定参数
CMD_PREFIX="./packer/kiteshield ./python"

# 后续固定参数
CMD_SUFFIX="1 mac_info.txt 1 puf_info.txt"

# 循环遍历第一个数字的取值范围 [1,4]
for i in {1..4}; do
    # 循环遍历第二个数字的取值范围 [5,6]
    for j in {5..6}; do
        # 循环遍历第三个数字的取值范围 [1,4]
        for k in {1..4}; do
            # 构建输出文件名
            OUTPUT_FILE="./combin_test_puf/python${i}${j}${k}"
            # 构建完整命令
            CMD="${CMD_PREFIX} ${i} ${j} ${k} ${OUTPUT_FILE} ${CMD_SUFFIX}"
            # 执行命令
            eval $CMD
        done
    done
done

# 脚本结束
