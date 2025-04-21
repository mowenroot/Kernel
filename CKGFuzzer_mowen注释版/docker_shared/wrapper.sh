#!/bin/bash

# Call your script. Replace 'your_script.sh' with the actual script name


# 切换到目标项目目录，$1 是脚本的第一个参数，表示项目的名称或路径
cd /src/$1

# 定义 build.sh 脚本的路径
script_path=/src/build.sh

# 检查 build.sh 文件是否存在
if [ ! -f "$script_path" ]; then
    # 如果文件不存在，输出错误信息并退出脚本，返回状态码为 1
    echo "Error: File '$script_path' does not exist."
    exit 1
fi

# 使用 grep 命令检查 build.sh 文件中是否包含命令 "bazel_build_fuzz_tests"
if grep -q "bazel_build_fuzz_tests" "$script_path"; then
    # 如果找到该命令，输出提示信息
    echo "The command 'bazel_build_fuzz_tests' is found in '$script_path'."
    
    # 将 /src/fuzzing_os/bazel_build 文件复制到 /usr/local/bin/ 目录下
    cp /src/fuzzing_os/bazel_build /usr/local/bin/
    
    # 使用 sed 命令将 build.sh 文件中的 "exec bazel_build_fuzz_tests" 替换为 "exec bazel_build"
    sed -i 's/exec bazel_build_fuzz_tests/exec bazel_build/g' $script_path
    
    # 注释掉以下行，表示可以选择替换 script_path 的值为另一个脚本路径（当前未启用）
    # script_path=/src/fuzzing_os/bazel_build.sh
else
    # 如果未找到该命令，输出提示信息
    echo "The command 'bazel_build_fuzz_tests' is not found in '$script_path'."
fi

# 执行 build.sh 脚本
bash $script_path

# 强制将脚本的退出状态码设置为 0，无论前面的命令执行结果如何
exit 0