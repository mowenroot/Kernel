from bs4 import BeautifulSoup
from collections import defaultdict
import os
import shutil
import tempfile
import re
from loguru import logger

from numpy import cov

class BranchState:
    def __init__(self, branch, bucket):
        self.branch = branch
        self.bucket = bucket

    @staticmethod
    def calculate_bucket_count(count):
        if count == 0:
            return 0
        bucket = count.bit_length() - 1
        return 1 << min(bucket, 31)


def html2txt(file_dir, coverage_dir):
    '''
    参数:
        file_dir: 存放 HTML 覆盖率报告的目录
        coverage_dir: 转换后的文件保存目录
    '''
    logger.info(file_dir)
    input(f"{logger.debug('mowen')}")
    # 如果输入目录不存在，则记录日志并返回
    if not os.path.exists(file_dir):
        logger.info(f"The coverage report {file_dir} directory does not exist.")
        return

    # Ensure coverage_dir exists
    os.makedirs(coverage_dir, exist_ok=True)

    files_processed = 0 # 累加已处理文件数
    # 遍历所有符合的html文件,抓取出覆盖率信息保存到 txt 中
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            # 筛选符合条件的 HTML 文件（.c.html, .cc.html, .cpp.html），且不包含 "fuzz_driver" 关键词
            if file.endswith(('.c.html', '.cc.html', '.cpp.html')) and 'fuzz_driver' not in file:
                files_processed += 1
                # 打开并读取 HTML 文件内容
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                #  使用 BeautifulSoup 解析 HTML 内容
                soup = BeautifulSoup(html_content, 'html.parser')
                output_text = ""
                # 查找所有的 table 元素（覆盖率信息一般保存在表格中）
                for table in soup.find_all('table'):
                    # 遍历每一行
                    for row in table.find_all('tr'):   
                        # 遍历每个单元格（表头和表格）     
                        for cell in row.find_all(['td', 'th']):
                            output_text += cell.get_text(strip=True) + "\t"
                        output_text += "\n"
                    output_text += "\n\n"
                # 构建输出 txt 文件名（去掉 .c/.cc/.cpp.html 的扩展）
                filename = file.split('.')[0]
                txt_file_path = os.path.join(coverage_dir, filename + '.txt')
                # 将提取后的文本写入到 txt 文件中
                with open(txt_file_path, 'w', encoding='utf-8') as f:
                    f.write(output_text)

                logger.info(f"Created: {txt_file_path}")

    if files_processed == 0:
        logger.info(f"No HTML files found in {file_dir}. Created empty coverage directory.")
            


def update_coverage_report(merge_dir, new_report_dir):
    '''
    参数：
        merge_dir: 当前累计的合并覆盖率报告目录
        new_report_dir: 新生成的覆盖率报告目录
    返回值：
        是否更新成功 (bool)
        最新行覆盖率、总行数、已覆盖行数
        最新分支覆盖率、总分支数、已覆盖分支数
        每个文件的分支覆盖率统计信息
    '''
    # 检查覆盖率提取的新目录是否不存在
    if not os.path.exists(new_report_dir):
        logger.info(f"The new report directory {new_report_dir} does not exist.")
        return False, 0, 0, 0, 0, 0, 0, {}
    # 检查目录是否空
    # Check if new_report_dir is empty
    if not os.listdir(new_report_dir):
        logger.info(f"The new report directory {new_report_dir} is empty.")
        return False, 0, 0, 0, 0, 0, 0, {}

    # Create merge_dir if it doesn't exist
    # 创建合并报告目录
    if not os.path.exists(merge_dir):
        os.makedirs(merge_dir)
        logger.info(f"Created merge directory: {merge_dir}")

    # 使用临时目录处理合并过程
    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy the current merge report to the temporary directory
        # 将当前的 merge_dir 到 临时目录
        shutil.copytree(merge_dir, temp_dir, dirs_exist_ok=True)
        
        # Update the temporary directory with the new report
        # 将新报告目录中的所有 txt 文件合并进临时目录
        for filename in os.listdir(new_report_dir):
            if filename.endswith('.txt'):
                temp_file = os.path.join(temp_dir, filename)
                new_file = os.path.join(new_report_dir, filename)
                # 如果临时目录中已存在该文件，进行内容合并
                if os.path.exists(temp_file):
                    update_file(temp_file, new_file)
                else:
                    # 否则直接复制新文件
                    shutil.copy2(new_file, temp_file)

        # Calculate coverages for the original merge directory and the temporary directory
        # 分别计算 原始、临时 的行覆盖率
        old_line_cov, old_total_lines, old_covered_lines = calculate_line_coverage(merge_dir)
        new_line_cov, new_total_lines, new_covered_lines = calculate_line_coverage(temp_dir)
        
        # 分别计算 原始、临时 的分支覆盖率
        old_branch_cov, old_total_branches, old_covered_branches = calculate_branch_coverage(merge_dir)
        new_branch_cov, new_total_branches, new_covered_branches = calculate_branch_coverage(temp_dir)
        # 计算每个文件的分支覆盖率
        file_coverages = calculate_files_branch_coverages(temp_dir)
        # 判断是否有新的分支被覆盖（核心判断标准）
        # 覆盖分支数 new > 旧覆盖分支数 old 
        new_branches_covered = new_covered_branches > old_covered_branches
        
        if new_branches_covered:
            # 如果发现新的分支被覆盖，更新 merge_dir（用临时目录覆盖原目录）
            shutil.rmtree(merge_dir)
            shutil.copytree(temp_dir, merge_dir)
            logger.info(f"New branches covered. Current covered branches: {new_covered_branches}, Previous covered branches: {old_covered_branches}. Merge report updated.")
            return True, new_line_cov, new_total_lines, new_covered_lines, new_branch_cov, new_total_branches, new_covered_branches, file_coverages
        else:
            logger.info(f"No new branches covered. Current covered branches: {new_covered_branches}, Previous covered branches: {old_covered_branches}. Merge report not updated.")
            return False, old_line_cov, old_total_lines, old_covered_lines, old_branch_cov, old_total_branches, old_covered_branches, file_coverages





def update_file(merge_file, new_file):
    with open(merge_file, 'r') as f:
        merge_lines = f.readlines()
    
    with open(new_file, 'r') as f:
        new_lines = f.readlines()
    
    updated_lines = []
    for merge_line, new_line in zip(merge_lines, new_lines):
        merge_count = extract_count(merge_line)
        new_count = extract_count(new_line)
        
        if merge_count is None and new_count is None:
            updated_lines.append(merge_line)
        elif merge_count is None:
            updated_lines.append(new_line)
        elif new_count is None:
            updated_lines.append(merge_line)
        else:
            max_count = max(merge_count, new_count)
            updated_line = re.sub(r'^\d+\|(\d+)\t', f'{max_count}\t', new_line)
            updated_lines.append(updated_line)
    
    with open(merge_file, 'w') as f:
        f.writelines(updated_lines)

def extract_count(line):
    parts = line.split('\t')
    if len(parts) >= 2:
        count_str = parts[1].strip()
        try:
            count = float(count_str.replace('k', '000'))
            return count if count > 0 else None
        except ValueError:
            return None
    return None


def calculate_line_coverage(merge_dir):
    ''' 
        统计被符号的行数 
        返回：行覆盖率、总行数、被覆盖行数
    '''
    total_lines = 0         # 总行数
    covered_lines = 0       # 覆盖行数
    # 遍历所有 txt 文件
    for filename in os.listdir(merge_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(merge_dir, filename)
            with open(file_path, 'r') as f:
                for line in f:
                    # 代码行定位 + 覆盖次数 + 代码
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        count_str = parts[1].strip()
                        if count_str and not count_str.startswith('Source'):
                            total_lines += 1
                            # 如果覆盖次数不是 0，说明这一行被覆盖了
                            if count_str != '0':
                                covered_lines += 1

    # print(f"total_lines: {total_lines}")
    # print(f"covered_lines: {covered_lines}")

    if total_lines > 0:
        coverage = covered_lines / total_lines
        return coverage,total_lines,covered_lines
    else:
        return 0,0,0




def calculate_branch_coverage(merge_dir):
    '''
        计算分支(if,switch等)覆盖度
        返回 : 分支覆盖率,总分支数,覆盖分支数
    '''
    total_branches = 0      # 总分支数
    covered_branches = 0    # 覆盖分支数
    # 没调用啊
    def parse_count(count_str):
        if count_str.endswith('k') or count_str.endswith('K'):
            return int(float(count_str[:-1]) * 1000)
        elif count_str.endswith('m') or count_str.endswith('M'):
            return int(float(count_str[:-1]) * 1000000)
        return int(float(count_str))  # Use float() to handle decimal points
    
    for filename in os.listdir(merge_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(merge_dir, filename)
            
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    parts = line.split('\t')
                    # 代码行定位 覆盖次数 代码
                    if len(parts) >= 3:
                        count_str = parts[1].strip()
                        code = parts[2].strip()
                        # 该行是否包含分支结构（ if、for 等）
                        branches = identify_branches(code, line_num)
                        for branch in branches:
                            total_branches += 1
                            if count_str and count_str != '0':
                                covered_branches += 1

    if total_branches > 0:
        coverage = covered_branches / total_branches
        return coverage, total_branches, covered_branches
    else:
        return 0, 0, 0
    

def calculate_single_branch_coverage(file_path):
    total_branches = 0
    covered_branches = 0


    def parse_count(count_str):
        if count_str.lower() == 'count':
            return 0  # Skip header row
        if count_str.endswith(('k', 'K')):
            return int(float(count_str[:-1]) * 1000)
        elif count_str.endswith(('m', 'M')):
            return int(float(count_str[:-1]) * 1000000)
        try:
            return int(float(count_str))
        except ValueError:
            return 0  # Return 0 for any non-numeric strings

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            parts = line.split('\t')
            if len(parts) >= 3:
                count_str = parts[1].strip()
                code = parts[2].strip()
                
                branches = identify_branches(code, line_num)
                for branch in branches:
                    total_branches += 1
                    if count_str and count_str != '0':
                        covered_branches += 1

    if total_branches > 0:
        coverage = covered_branches / total_branches
        return coverage, total_branches, covered_branches
    else:
        return 0, 0, 0
    

def calculate_files_branch_coverages(directory):
    '''
        单个文件的分支覆盖率
        返回: 字典 key 为文件名, value 为覆盖情况(覆盖率,总分支数,覆盖分支数)
    '''
    file_coverages = {}
    if not os.path.exists(directory):
        logger.warning(f"Merge directory does not exist: {directory}")
        return file_coverages

    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                coverage, total_branches, covered_branches = calculate_single_branch_coverage(file_path)
                file_coverages[filename] = {
                    'coverage': coverage,
                    'total_branches': total_branches,
                    'covered_branches': covered_branches
                }
            except Exception as e:
                logger.error(f"Error processing file {filename}: {str(e)}")

    return file_coverages


def sort_and_filter_coverages(file_coverages, threshold):
    ''' 用于对文件覆盖率数据进行排序，并筛选出低于指定阈值的文件 '''
    sorted_coverages = sorted(file_coverages.items(), key=lambda x: x[1]['coverage'])
    low_coverage_files = [filename for filename, data in sorted_coverages if data['coverage'] < threshold]
    return sorted_coverages, low_coverage_files


def identify_branches(code, line_num):
    ''' 正则判断是否为分支结构( if , switch 等 ) '''
    branches = []
    # 定义常见的分支结构对应的正则表达式和其类型标识
    branch_patterns = [
        (r'\bif\s*\(', 'if'),                  # if ( 条件 )
        (r'\belse\s+if\s*\(', 'else if'),      # else if ( 条件 )
        (r'\belse\b', 'else'),                 # else

        (r'\bswitch\s*\(', 'switch'),          # switch ( 变量 )
        (r'\bcase\b', 'case'),                 # case 标签:
        (r'\bdefault\s*:', 'default'),         # default:

        (r'\bfor\s*\(', 'for'),                # for ( 初始化; 条件; 更新 )
        (r'\bwhile\s*\(', 'while'),            # while ( 条件 )
        (r'\bdo\b', 'do'),                     # do { ... } while 条件

        (r'\?.*:.*', 'ternary'),               # 三目运算符：cond ? expr1 : expr2

        (r'\|\|', 'logical or'),               # 逻辑或
        (r'&&', 'logical and'),                # 逻辑与

        (r'\bgoto\b', 'goto'),                 # goto 标签
        (r'\blabel:.*', 'label'),              # 标签（label: xxx）

        (r'\btemplate\s*<', 'template'),       # 模板定义：template<typename T>
        (r'\bvirtual\b', 'virtual function'),  # 虚函数声明
        (r'\breturn\b', 'return'),             # return 语句

        (r'\btry\b', 'try'),                   # try 块
        (r'\bcatch\s*\(', 'catch'),            # catch ( 异常类型 )
        (r'\bthrow\b', 'throw'),               # throw 异常
    ]
    # 遍历每种分支模式，对当前代码行进行匹配
    for pattern, branch_type in branch_patterns:
        # 正则匹配
        if re.search(pattern, code):
            branches.append((line_num, branch_type))
    
    return branches
    
