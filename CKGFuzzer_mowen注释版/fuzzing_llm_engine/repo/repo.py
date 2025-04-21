## agent_repo.py
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录
parent_dir = os.path.dirname(current_dir)
# 将父目录添加到 sys.path
sys.path.insert(0, parent_dir)
#from pathlib import Path
import getpass
from loguru import logger
import json    
from typing import List, Dict
from utils.docker_run import docker_run, check_image_exists, create_image
from utils.query_dp import run_query, run_converted_csv,run_command, add_codeql_to_path
import subprocess
from utils import check_create_folder, check_path_test, find_cpp_head_files
# from pandas import DataFrame
# import pandas as pd
from loguru import logger
from codetext.parser.cpp_parser import CppParser
# from tools.codetext.utils import build_language, parse_code
import collections
from multiprocessing import Pool,Manager
from tqdm import tqdm
import shutil
import docker
add_codeql_to_path()
# Get the current PATH
current_path = os.environ['PATH']
# logger.info(f"PATH: {current_path}")
# logger.add("repo_log.txt")

from utils.repo_fn import clean_label, change_folder_owner, get_all_files, copy_file_to_tmp_get_definition
        
manager = Manager() 
# created a size limited queue
queue_id = manager.Queue()


import shutil

import chardet

            
class RepositoryAgent:
    def __init__(self, args: Dict = None):
        """
        Initializes the PlanningAgent with the extracted API information.

        Args:
            api_info (Dict, optional): Extracted API information to be used for planning fuzzing tasks. Defaults to None.
        """
        #super().__init__()
        self.args = args
        self.shared_llm_dir = args.shared_llm_dir
        self.src_folder = f'{args.shared_llm_dir}/source_code/{args.project_name}'
        self.queryes_folder = f'{args.shared_llm_dir}/qlpacks/cpp_queries/'
        self.database_db = f'{args.shared_llm_dir}/codeqldb/{args.project_name}'
        self.output_results_folder = f'{args.saved_dir}'
        # 检查输出目录
        check_create_folder(self.output_results_folder)

        # 检查代码库是否存在
        self.init_repo()
        

    def init_repo(self) -> List[str]:
        """
        Initializes the repository with the provided arguments.
            1. Add the repo to the database codeql.
            2. Extract API Info.
        """
        # 检查codeqldb是否存在
        if os.path.isfile(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created'):
            # logger.info(f"Database for {args.project_name} already exists.")
            pass
            # print(f"Database for {args.project_name} already exists.")
        else:
            # 如果不存在，开始创建database
            self._add_local_repo_to_database(self.args)
        
        if not os.path.isdir(f'{self.src_folder}'):
            logger.info(f"{args.project_name} does not exist.")
            self.copy_source_code_fromDocker()


    def _add_local_repo_to_database(self, args: Dict) -> None:
        # 获取用户名
        USER_NAME = getpass.getuser()
        # 获取项目目录
        project_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'projects', args.project_name)
        # 目录指向 fuzzing_llm_engine/projects/*   /home/mowen/CKGFuzzer_mowen/fuzzing_llm_engine/projects/c-ares
        logger.debug(f"mowen: {project_dir}")
        dockerfile_path = os.path.join(project_dir, 'Dockerfile')
        # 目录下面包括 build.sh dockerfile project.yaml
        if not os.path.exists(dockerfile_path):
            raise FileNotFoundError(f"Dockerfile not found at {dockerfile_path}")
        # image_name == c-ares_base_image
        image_name = f'{args.project_name}_base_image'
        build_command = f'docker build -t {image_name} -f {dockerfile_path} {project_dir}'
        # 准备docker启动命令 -t 指定构建docker的tag -f 指定dockerfile的目录 最后跟上项目dir
        # 构建docker镜像
        Isin_dockerimg = False
        client = docker.from_env()
        print(client.images.list())
        for img in client.images.list():
            for tag in img.tags:
                print(img,tag,image_name)
                if  tag.startswith(image_name):  
                    logger.info(f"Image {image_name} already exists.")
                    Isin_dockerimg = True
                    break
            if Isin_dockerimg:
                break

        if  not Isin_dockerimg :
            logger.info(f"Image {image_name} does not exist.")
            try:
                subprocess.run(build_command, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to build Docker image: {e}")
                return
           
        # 需要确保 codeql 目录存在，但是项目目录文件夹为空，否则codeql 数据库会构建失败
        if not os.path.exists(f'{args.shared_llm_dir}/codeqldb'):
            logger.info(f"Create {args.shared_llm_dir}/codeqldb")
            os.makedirs(f'{args.shared_llm_dir}/codeqldb')
        if os.path.exists(f'{args.shared_llm_dir}/codeqldb/{args.project_name}'):
            logger.info(f"Database for {args.project_name} already exists.")
            shutil.rmtree(f'{args.shared_llm_dir}/codeqldb/{args.project_name}')
            return

        # Prepare the CodeQL command
        # 创建 codql 数据库
        codeql_command = f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language}'
        
        if args.language in ['c', 'cpp', 'c++', 'java', 'csharp', 'go', 'java-kotlin']:
            codeql_command += f' --command="/src/fuzzing_os/wrapper.sh {args.project_name}"'

        # Run the Docker container with the CodeQL command
        command = [
            'docker', 'run', '--rm', # --rm 运行完自动删除
            '-e',f'FUZZING_LANGUAGE={args.language}',
            '-v', f'{args.shared_llm_dir}:/src/fuzzing_os', # 映射卷，把本地的 shared_llm_dir 挂载到容器中的 /src/fuzzing_os
            '-t', image_name,
            '/bin/bash', '-c', codeql_command
        ]
        # 在 docker中执行 codeql 指令
        logger.debug(f"cmd -> {' '.join(command)}")
        result = subprocess.run(command, text=True,capture_output=True)
        # 更改文件夹所有者，因为docker中是root用户，映射出来有问题
        change_folder_owner(f"{args.shared_llm_dir}/change_owner.sh", f'{args.shared_llm_dir}/codeqldb/{args.project_name}', USER_NAME)
        if f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}" in result.stdout:
            with open(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created', 'w') as f:
                f.write('')
            logger.info(result.stdout)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")

            with open ("/tmp/codeql.log",'w') as f :
                f.write(result.stdout)
        else:
            print(result.stdout)
            print(result.stderr)
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"

    def _add_repo_to_database(self, args: Dict) -> None:
        image_name = f'gcr.io/oss-fuzz/{args.project_name}'
        if not check_image_exists(image_name):
            create_image(args.project_name)
            
        # USER_NAME = getpass.getuser()
        if args.language in ['c','cpp', 'java', 'csharp','go', 'java-kotlin']:
            logger.info(f"args.shared_llm_dir {args.shared_llm_dir}")
            command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', '-t', f'gcr.io/oss-fuzz/{args.project_name}', '/bin/bash', '-c', f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language}  --command="/src/fuzzing_os/wrapper.sh {args.project_name}" && chown -R 1000:1000 /src/fuzzing_os/codeqldb/{args.project_name}' ] # --command="/src/fuzzing_os/wrapper.sh {args.project_name} --source-root={args.project_name}
        else:
            command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', '-t', f'gcr.io/oss-fuzz/{args.project_name}', '/bin/bash', '-c', f'/src/fuzzing_os/codeql/codeql database create /src/fuzzing_os/codeqldb/{args.project_name} --language={args.language} && chown -R 1000:1000 /src/fuzzing_os/codeqldb/{args.project_name}' ] # --source-root={args.project_name}
        result,_ = docker_run(command, print_output=True, architecture='x86_64')
        #change_folder_owner(f"{args.shared_llm_dir}/change_owner.sh",f'{args.shared_llm_dir}/codeqldb/{args.project_name}', USER_NAME)
        if f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}" in result:
            with open(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created', 'w') as f:
                f.write('')
            logger.info(result)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")
        else:
            logger.info(result)
            logger.info(f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}" )
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"    
    

    # read the function name and its source code name from the returned dict of extract_api_from_head
    def extract_src_test_api_call_graph(self, data: Dict, pool_num=4) -> Dict:
        """
            提取源码和测试代码中的 API 调用图(Call Graph)
            支持多线程并行提取，每个线程用一份数据库副本。
        ToDO: multple thread SUPPORT, need to keep the copy database for each thread
        Extracts the source and test API information from the repository.
        """
        logger.info("Extracting source and test API information from the repository.")
        src_api = []
        # 每个文件中提取出 fn_def_list(函数定义列表)
        for src_file in data['src']:
            fn_def_list = data['src'][src_file]['fn_def_list']
            #  遍历函数定义，取出每个函数的名字
            for item in fn_def_list:
                fn_name = item['fn_meta']['identifier']
                # 原始路径替换为容器内的路径 /src/，供 docker 中的 codeql 使用
                src_api.append((fn_name, src_file.replace(f'{args.shared_llm_dir}/source_code/', '/src/')))
                # (函数名, 文件路径) example    ->    ('jni_get_class', '/src/c-ares/src/lib/ares_android.c')

        
        '''
            构造一个任务列表 eggs,包含每个函数所需的信息
            [函数名,
            文件路径,
            CodeQL 数据库路径,
            输出结果文件夹路径,
            LLM 工作目录路径]
        '''
        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
        logger.info("Copy Database for each thread.")
        # 多线程处理，为每个线程拷贝一份数据库
        # docker_shared/codeqldb/project ->(copy)  docker_shared/codeqldb/project_n 
        for i in tqdm(range(pool_num)):
            shutil.copytree(self.database_db, f'{self.database_db}_{i}', dirs_exist_ok=True)
            # 把线程编号放入一个线程安全的队列中，供工作线程分配任务时使用
            queue_id.put(i)
        # 并发运行 handle_extract_api_call_graph_multiple_path 函数
        with Pool(pool_num) as pool:   
            results = list(tqdm(pool.imap(RepositoryAgent.handle_extract_api_call_graph_multiple_path, eggs), total=len(eggs), desc='Processing transactions'))     

        # 删除拷贝用的临时数据库
        for i in range(pool_num):
            shutil.rmtree(f'{self.database_db}_{i}')

    @staticmethod
    def handle_extract_api_call_graph_multiple_path(item):
        global queue_id
        pid = os.getpid()  # Get the current process ID
        # 从 queue_id 队列中取出一个数据库副本编号（bid）。
        bid = queue_id.get()
        logger.info(f"============================ {pid} Consuming {bid}")
        fn_name, fn_file_name, dbbase, outputfolder, shared_llm_dir = item
        # 调用 _extract_call_graph 方法执行 API 调用图提取逻辑
        RepositoryAgent._extract_call_graph(shared_llm_dir, fn_name, fn_file_name, f"{dbbase}_{bid}", outputfolder, bid)
        queue_id.put(bid)

    @staticmethod
    def _extract_call_graph(shared_llm_dir, fn_name, fn_file_name, dbbase, outputfolder, pid):
        """
            Extracts the call graph from the repository.
            从代码仓库中提取某个函数的调用图

            shared_llm_dir: 映射的主机目录根路径，存放查询脚本等。
            fn_name: 函数名。
            fn_file_name: 函数所在文件名。
            dbbase: codeql 副本数据库的路径
            outputfolder: 提取结果输出目录。
            pid: 当前进程的编号

        """
        logger.info("Extracting call graph from the repository.")
        extract_shell_script = f"{shared_llm_dir}/qlpacks/cpp_queries/extract_call_graph.sh"
        pname = fn_file_name.replace('/', '_')
        if os.path.isfile(extract_shell_script):
            if not os.path.isfile(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs"):
                logger.info(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs")
                # convert dbbase and outputfolder to the absolute path
                dbbase = os.path.abspath(dbbase)
                outputfolder = os.path.abspath(outputfolder)
                #fn_name="ares__dns_options_free"
                logger.info(f"Extracting call graph for {fn_name} in {fn_file_name}.")
                
                run_command([extract_shell_script, fn_name, fn_file_name, dbbase, outputfolder, str(pid)])
                logger.info("Call graph is converted into the csv file.")
                #fn_file="${fn_file//\//_}"
            if not os.path.isfile(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.csv"):
                run_converted_csv(f"{outputfolder}/call_graph/{pname}@{fn_name}_call_graph.bqrs")  
        else:
            assert False, f"Extract call graph shell script {extract_shell_script} does not exist. PWD {os.getcwd()}"
              
    def copy_source_code_fromDocker(self):
        """
        Extracts the source code from the repository.
        """
        logger.info("Extracting source code from the repository.")
        
        # First, create the necessary directories
        mkdir_command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', 
                        '-t', f'{args.project_name}_base_image', 
                        '/bin/bash', '-c', 
                        f'mkdir -p /src/fuzzing_os/source_code/{args.project_name}']
        docker_run(mkdir_command)
        
        # Then, copy the source code
        copy_command = ['-v', f'{os.path.abspath(args.shared_llm_dir)}:/src/fuzzing_os', 
                        '-t', f'{args.project_name}_base_image', 
                        '/bin/bash', '-c', 
                        f'cp -rf /src/{args.project_name}/* /src/fuzzing_os/source_code/{args.project_name} && '
                        f'chown -R 1000:1000 /src/fuzzing_os/source_code/{args.project_name}']
        docker_run(copy_command)



    def scan_vulnerability_qlCWE(self):
        """
        Scan the repository for vulnerabilities.
        """
        logger.info("Scanning the repository for vulnerabilities.")
        os.makedirs(f'{self.output_results_folder}/vulnerability', exist_ok=True)
        output_file = f'{self.output_results_folder}/vulnerability/CWE.sarif'
        command = [ "codeql", "database", "analyze", f"{self.database_db}","codeql/cpp-queries:codeql-suites/cpp-security-extended.qls", "--format=sarifv2.1.0", f"--output={output_file}", "--download" ]
        run_command(command)
    
    def scan_vulnerability_extended_CWE(self):
        """
        Scan the repository for the extened vulnerabilities.
        """
        logger.info("Scanning the repository for extended vulnerabilities.")
        os.makedirs(f'{self.output_results_folder}/vulnerability', exist_ok=True)
        output_file = f'{self.output_results_folder}/vulnerability/CWE_extend.sarif'
        command = [ "codeql", "database", "analyze", f"{self.database_db}","codeql/cpp-queries:codeql-suites/cpp-code_qlrules.qls", "--format=sarif", f"--output={output_file}", "--download"]
        run_command(command)
    
    def extract_api_from_head(self):
        # 判断项目源码是否存在，直接从docker映射出来，相对路径为 docker_shared/source_code/{project_name}
        if not os.path.isdir(self.src_folder): 
            logger.info(f"{self.src_folder} does not exist.")
            # 如果不存在需要从 docker 中 copy 出来
            self.copy_source_code_fromDocker()
        
        logger.info(f"Extracting API information from the source code. {self.src_folder}")
        # src_dic 为 项目中的头文件 + c/cpp文件 
        # test_dic 为 项目中的测试文件 
        src_dic, test_dic = find_cpp_head_files(self.src_folder)    

        logger.info(f"Number of source files: {len(src_dic['src'])}")
        logger.info(f"Number of header files: {len(src_dic['head'])}")
        # 如果 头文件不存在
        if not src_dic['head']:
            logger.warning("No header files found!")
            # 遍历所有文件并打印文件路径
            for root, dirs, files in os.walk(self.src_folder):
                logger.debug(f"Directory: {root}")
                for file in files:
                    logger.debug(f"File: {os.path.join(root, file)}")

        logger.info("Extracting API information from the source code.")
        logger.debug(f"src_dic -> {src_dic}")
        # 提取API信息
        result_src = self._extract_API(src_dic)
        logger.info("Extracting API information from the test code.")
        result_test= self._extract_API(test_dic)
        logger.info(f"Store API to {self.output_results_folder}/api/")
        os.makedirs(f'{self.output_results_folder}/api', exist_ok=True)
        # 保存文件列表
        json.dump(result_src, open(f'{self.output_results_folder}/api/src_api.json', 'w'), indent=2)
        json.dump(result_test, open(f'{self.output_results_folder}/api/test_api.json', 'w'), indent=2)
        return result_src, result_test
    
    import chardet

    def _extract_API(self, src_dic):
        # 嵌套字典
        result = collections.defaultdict(dict)
        for k in ['src', 'head']:
            logger.info(f"Processing {k} files")
            # 遍历所有 src/head 文件
            for src in src_dic[k]:
                logger.info(f"Processing file: {src}")
                # 读取文件内容，这里做了兼容性处理，如果文件编码无法识别，则尝试使用 latin1 编码读取
                try:
                
                    with open(src, 'r', encoding='utf-8') as file:
                        code = file.read()
                except UnicodeDecodeError:
                 
                    with open(src, 'rb') as file:
                        raw = file.read()
                        detected = chardet.detect(raw)
                        encoding = detected['encoding']
                    
                   
                    try:
                        code = raw.decode(encoding)
                    except:
                        logger.error(f"Failed to decode {src} with detected encoding {encoding}. Skipping this file.")
                        continue

                try:
                    '''
                        fn_def_list: 函数定义列表

                        fn_declaraion: 函数声明列表

                        class_node_list: 类定义

                        struct_node_list: 结构体定义

                        include_list: 包含的头文件

                        global_variables: 全局变量

                        enumerate_node_list: 枚举类型
                    '''
                    # 提取c/cpp中的相应结构，
                    # is_return_node: 是否返回抽象语法树（AST）节点对象（True 返回 AST 节点，False 返回可序列化信息，如字符串 + 位置）
                    fn_def_list, fn_declaraion, class_node_list, struct_node_list, include_list, global_variables, enumerate_node_list = CppParser.split_code(code, is_return_node=False)
                    result[k][src] = {
                        'fn_def_list': fn_def_list,
                        'fn_declaraion': fn_declaraion,
                        'class_node_list': class_node_list,
                        'struct_node_list': struct_node_list,
                        'include_list': include_list,
                        "global_variables": global_variables,
                        "enumerate_node_list": enumerate_node_list
                    }
                    logger.info(f"Successfully processed {src}")
                    logger.info(f"Found {len(fn_def_list)} function definitions, {len(fn_declaraion)} function declarations, {len(class_node_list)} classes, {len(struct_node_list)} structs")
                
                    
                    debug_output_path = f'{src}.debug.json'
                    with open(debug_output_path, 'w') as f:
                        json.dump(result[k][src], f, indent=2)
                    logger.info(f"Debug output written to {debug_output_path}")
                
                except Exception as e:
                    logger.error(f"Error processing {src}: {str(e)}")
                    continue

        logger.info(f"Finished processing all files. Found data for {len(result['src'])} source files and {len(result['head'])} header files.")
        return result
    




import os    
import argparse
import repo.constants as constants

def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Example application")
    parser.add_argument('--project_name', type=str, default="c-ares", help='Project Name')
    parser.add_argument('--shared_llm_dir', type=str, default="../docker_shared", help='Shared LLM Directory')
    parser.add_argument('--saved_dir', type=str, default="./external_database/c-ares/codebase", help='Saved Directory')
    parser.add_argument('--language', type=str, default="c++", help='Language')
    parser.add_argument('--build_command', type=str, default="/src/fuzzing_os/build_c_ares.sh", help='Build command')
    parser.add_argument('--project_build_info', type=str, default=None, help='Build information of the project')
    parser.add_argument('--environment_vars', dest='environment_vars', action='append', help="Set environment variable e.g., VAR=value")
    parser.add_argument('--engine', default=constants.DEFAULT_ENGINE, choices=constants.ENGINES, help='Engine used for building')
    parser.add_argument('--architecture', default=constants.DEFAULT_ARCHITECTURE, choices=constants.ARCHITECTURES, help='CPU architecture')
    parser.add_argument('--sanitizer', default=None, choices=constants.SANITIZERS, help='Sanitizer type')
    parser.add_argument('--src_api', action='store_true', help='Source API')
    parser.add_argument('--test_api', action='store_true', help='Test API version')
    parser.add_argument('--call_graph', action='store_true', help='Call graph')
    parser.add_argument('--cwe_scan', action='store_true', help='CWE Scan')
    return parser
    
if __name__ == "__main__":
    parser = setup_parser()
    args = parser.parse_args()
    r = RepositoryAgent(args)
    
    logger.info(f"The current work path is: {os.getcwd()}")
    result_src, result_test = None, None
    if args.src_api:
        
        result_src, result_test = r.extract_api_from_head()
    
    
    if args.cwe_scan:
        r.scan_vulnerability_qlCWE()
        # r.scan_vulnerability_extended_CWE()
    
    if args.call_graph:
        
        if result_src is None and result_test is None:
            result_src, result_test = r.extract_api_from_head()
        r.extract_src_test_api_call_graph(result_src)
        

 
  