#!/bin/bash

# 立即退出脚本，如果任何命令返回非零状态
set -e  

# 获取当前脚本的完整路径
script_path=$(realpath "$0")  

# 提取脚本所在的目录路径
script_dir=$(dirname "$script_path")  
# 切换到脚本所在的工作目录
cd "$script_dir"  

# 从参数中获取函数名、文件路径、数据库路径、输出文件夹和进程ID
fn_name=$1  # 函数名
fn_file=$2  
fn_file="${fn_file//\//_}"   # 文件路径（替换斜杠为下划线）
dbbase=$3   # codeql数据库路径
outputfolder=$4  # 输出文件夹路径
pid=$5      # 进程ID

# 打印相关信息
echo "Script Dir ====== $script_dir"
echo "Database path: $dbbase"
echo "Output folder: $outputfolder"
echo "Process ID: $pid"

# 检查输出文件夹是否存在，不存在则创建
[ -d "$outputfolder/call_graph" ] || mkdir -p "$outputfolder/call_graph"  

# 定义输出文件路径
outputfile="$outputfolder/call_graph/${fn_file}@${fn_name}_call_graph.bqrs"  

# 定义查询模板文件路径
QUERY_TEMPLATE="./extract_call_graph_template.ql"  
# 定义生成的查询文件名
QUERY="call_graph_${pid}.ql"  

# 打印信息：复制模板并生成查询文件
echo "Copying template and generating query file..."  
# 复制查询模板到生成的查询文件
cp "$QUERY_TEMPLATE" "$QUERY"  
# 使用sed命令将模板中的占位符ENTRY_FNC替换为实际函数名
sed -i "s/ENTRY_FNC/$fn_name/g" "$QUERY"  

# 打印信息：运行CodeQL查询
echo "Running query: codeql query run $QUERY --database=$dbbase --output=$outputfile"  
# 执行CodeQL查询
if codeql query run "$QUERY" --database="$dbbase" --output="$outputfile"; then  
    # 如果查询成功，打印信息：转换BQRS文件为CSV
    echo "Query executed successfully. Converting BQRS to CSV."  
    # 定义CSV输出文件路径
    csv_output="${outputfile%.bqrs}.csv"  
    # 将BQRS文件解码为CSV格式
    if codeql bqrs decode --format=csv "$outputfile" --output="$csv_output"; then  
        # 如果转换成功，打印信息
        echo "BQRS file successfully converted to CSV: $csv_output"
    else
        # 如果转换失败，打印错误信息并退出
        echo "Error converting BQRS to CSV"
        exit 1
    fi
else
    # 如果查询失败，打印错误信息并退出
    echo "Error executing CodeQL query"
    exit 1
fi

# 删除临时生成的查询文件
rm "$QUERY"  