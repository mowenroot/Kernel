import os
import sys
from loguru import logger


## agent_repo.py
import sys
from pathlib import Path
import getpass
import shlex 
import os
import glob

# # Add the project root to the Python path
# root_path = str(Path(__file__).resolve().parent.parent.parent)  # Adjust the number of parents based on submodule depth
# print(root_path)
# if root_path not in sys.path:
#     sys.path.append(root_path)

def _get_command_string(command):
  """Returns a shell escaped command string."""
  return ' '.join(shlex.quote(part) for part in command)

def check_create_folder(folder_path):
    """
    Check if the folder exists, if not create it.
    """
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Created folder: {folder_path}")


def check_path_test(path):
    """
    Check if the path contains 'test' folder or '_test' in the file name.
    """
    # Split the path into parts
    path = path.lower()
    parts = path.split(os.sep)
    # Check if 'test' is a directory in the path
    has_test_folder = 'test' in parts[:-1]  # Ignore the last part since it's a file
    # Check if the file name contains '_test'
    has_test_in_filename = '_test' in parts[-1] or 'test_' in parts[-1] or "-test" in parts[-1]
    return has_test_folder or has_test_in_filename

def find_cpp_head_files(directory):
    source_files = {"src": [], "head": []}
    test_files = {"src": [], "head": []}
    
    src_extensions = {'.c', '.cpp', '.c++', '.cxx', '.cc', '.C'}
    head_extensions = {'.h', '.hpp', '.h++', '.hxx', '.hh', '.H', '.inl', '.inc'}

    logger.info(f"Searching for files in: {directory}")
    # 遍历文件夹 （当前目录，子目录，文件）
    for root, _, files in os.walk(directory):
        for file in files:
            # 获取当前文件的路径
            file_path = os.path.join(root, file)
            # 拆分文件名和后缀
            _, ext = os.path.splitext(file)
            
            logger.debug(f"Processing file: {file_path}")
            # 搜集 头文件和 c/cpp 文件,并区分是否包含test
            if ext in src_extensions:
                #  check_path_test 检测文件名是否包含test
                if check_path_test(file_path):
                    test_files["src"].append(file_path)
                    logger.debug(f"Added to test_src: {file_path}")
                else:
                    source_files["src"].append(file_path)
                    logger.debug(f"Added to source_src: {file_path}")
            elif ext in head_extensions:
                if check_path_test(file_path):
                    test_files["head"].append(file_path)
                    logger.debug(f"Added to test_head: {file_path}")
                else:
                    source_files["head"].append(file_path)
                    logger.debug(f"Added to source_head: {file_path}")

    logger.info(f"Found {len(source_files['src'])} source files and {len(source_files['head'])} header files.")
    logger.info(f"Found {len(test_files['src'])} test source files and {len(test_files['head'])} test header files.")
    # 返回 文件
    return source_files, test_files