import os,sys

from sympy import Plane
# from configs.log import setup_logger
from loguru import logger
# Get the current working directory
current_work_dir = os.getcwd()
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))
logger.info(f"Current workding dir: {current_work_dir}")
logger.info(f"Project Root and Append to the system path: {project_root}")
# 添加项目根目录到环境变量中
sys.path.append(project_root)

from roles import input_gen_agent
from roles import planner
from roles import fuzz_generator
from roles import run_fuzzer
from roles import crash_analyzer
from roles import compilation_fix_agent
import shutil
import yaml
import subprocess
import shlex
from models.get_model import get_model
from models.get_model import get_embedding_model
import json
from rag.query_engine_factory import build_test_query, build_cwe_query,build_kg_query
from rag.hybrid_retriever import CodeGraphRetriever
from llama_index.core import Settings
# 检测 Docker 容器是否正在运行
def is_docker_container_running(project_name):
    """Check if a Docker container is running."""
    try:
        # docker ps --filter name=c-ares_check --format {{.Names}}
        docker_cmd = ['docker', 'ps', '--filter', f'name={project_name}_check', '--format', '{{.Names}}']
        logger.debug(f"docker_cmd -> {' '.join(docker_cmd)}")
        result = subprocess.run(
            docker_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if project_name+"_check" in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error checking Docker container status: {e}")
        return False
    
def extract_api_list(api_code_file):
    try:
        with open(api_code_file, 'r', encoding='utf-8') as f:
            src_api_code = json.load(f)
        
        api_list = list(src_api_code.keys())
        return api_list
    except Exception as e:
        logger.error(f"Error extracting API list from source code: {str(e)}")
        return []

def initialize_api_usage_count(api_list):
    api_usage_count = {api: 0 for api in api_list}
    return api_usage_count
    
import argparse
def args_parser():
    parser = argparse.ArgumentParser(description='Description of fuzzing settings')
    parser.add_argument('--yaml', type=str, default="")
    parser.add_argument("--gen_driver", action='store_true', default=True, help="Fuzz Driver Generation")
    parser.add_argument("--skip_gen_driver", dest='gen_driver', action='store_false', help="Skip Fuzz Driver Generation")
    parser.add_argument("--summary_api", action='store_true', default=True, help="Summary API")
    parser.add_argument("--skip_summary_api", dest="summary_api", action="store_false", help="Skip Summary API")
    parser.add_argument("--check_compilation", action='store_true', default=True, help="Check Compilation")
    parser.add_argument("--skip_check_compilation", dest='check_compilation',action='store_false', help='Skip Check Compilation')
    parser.add_argument("--gen_input", action='store_true', default=True, help="Generate Input")
    parser.add_argument("--skip_gen_input", dest='gen_input',action='store_false', help='Skip Generate Input')
    args = parser.parse_args()
    return args
        

# 启动一个 Docker 准备检查 fuzz 代码是否可以成功编译
def start_docker_for_check_compilation(project_dir, project_name):
    # 检测 project_name 的容器是否正在运行
    if is_docker_container_running(project_name):
        logger.info(f"Docker container '{project_name}_check' is already running. Continuing...") 
        return True
    else:
        # 如果不在运行, 启动一个 Docker
        logger.info(f"Docker container '{project_name}_check' is not running. Starting...")
        try:
            # 利用 check_gen_fuzzer.py 脚本启动 docker
            # 没做 docker images 是否已经存在的检查 
            docker_start_command = f"python  {project_dir}fuzzing_llm_engine/utils/check_gen_fuzzer.py start_docker_check_compilation {project_name} --fuzzing_llm_dir {project_dir}docker_shared/"
            logger.debug(f"docker_start_command: \n{docker_start_command}")
            subprocess.run(shlex.split(docker_start_command), check=True)
            logger.info("Docker for check compilation started successfully.")
            return True
        except subprocess.CalledProcessError as e:
            logger.info(f"Error starting Docker for check compilation: {e}")
            return False



if __name__ == '__main__':
    args = args_parser()

    # 加载 config
    if args.yaml is not None and os.path.isfile(args.yaml):
        with open(os.path.join(args.yaml), 'r') as file:
             config = yaml.safe_load(file)
    # 从 config.yaml 中获取项目配置信息
    project_config = config['config']
    project_name = project_config['project_name']
    program_language = project_config['program_language']
    fuzz_projects_dir = project_config['fuzz_projects_dir']
    work_dir = project_config['work_dir']
    shared_dir = project_config['shared_dir']
    time_budget = project_config['time_budget']
    report_target_dir = project_config['report_target_dir']
    
    # 加载基本文件路径 : 三个聚合文件、agents_result、fuzz_dir( CKGFuzzer_mowen/fuzzing_llm_engine )
    api_summary_file = os.path.join(fuzz_projects_dir, "api_summary/api_with_summary.json")
    api_code_file = os.path.join(fuzz_projects_dir, "src/src_api_code.json")
    api_call_graph_file = os.path.join(fuzz_projects_dir, "api_combine/combined_call_graph.csv")
    agents_result_dir = os.path.join(fuzz_projects_dir, "agents_results")
    fuzz_dir=os.path.join(work_dir,"fuzzing_llm_engine/")

    # parameters for construting graph knowledge
    # 构造图参数
    chromadb_dir = os.path.join(fuzz_projects_dir, "chromadb/") 
    call_graph_csv = api_call_graph_file
    all_src_api_file = os.path.join(fuzz_projects_dir, "codebase/api/src_api.json")
    kg_saved_folder = fuzz_projects_dir
    exclude_folder_list=[]

    # 头参数
    headers= project_config['headers'] 
    

    logger.info(f"Init LLM Models, config {config}")
    
    # code model for generation and fix
    '''
        检查配置文件中是否包含 llm_coder 或 llm_analyzer 的配置项。 
        这两个配置用来调用 LLM 模型，用于生成代码和修复代码。
        如果没有找到这两个配置项，则抛出断言错误。
    '''
    # 生成文本的语言模型
    assert "llm_coder" in config or "llm_analyzer" in config, "your config file has to contain at least the llm_coder config or llm_analyzer config"
    # 获取 llm model coder 版本，如果 config 中没有 llm_coder，则使用 llm_analyzer 的配置。
    llm_coder = get_model(config["llm_coder"] if "llm_coder" in config else config["llm_analyzer"])
    # code model for combination，summary
    llm_analyzer = get_model(config["llm_analyzer"] if "llm_analyzer" in config else config["llm_coder"] )
    
    # 文本向量化模型
    # 和上面的 llm 逻辑一致
    assert "llm_embedding" in config or "llm_code_embedding" in config, "your config file has to contain at least the llm_embedding config or llm_code_embedding config"
    # common text embedding model
    llm_embedding= get_embedding_model(config["llm_embedding"]  if "llm_embedding" in config else config["llm_code_embedding"] ) 
    # code embedding model
    llm_embedding_coding = get_embedding_model(config["llm_code_embedding"] if "llm_code_embedding" in config else config["llm_embedding"])

    # set default LLM settings
    # 设置默认 LLM 设置
    Settings.llm = get_model(None)
    #Settings.embed_model = get_embedding_model(None, device='cuda:1')
    Settings.embed_model = get_embedding_model(None, device='cpu')
    logger.info(f"Init Default LLM Model and Embedding Model, LLM config: { Settings.llm.metadata } \n Embed config: {Settings.embed_model}")

        
    logger.info(f"Init API Combine Query and Test Query Engine")
    
    # test 文件的索引存储 ，以修复生成的模糊驱动程序
    test_case_index = build_test_query(fuzz_projects_dir, llm=llm_analyzer, embed_model=llm_embedding)
    # CWE 文件的索引存储
    cwe_index = build_cwe_query(fuzz_dir, llm=llm_analyzer, embed_model=llm_embedding)
    
    query_tools = {}
    query_tools["test_case_index"] = test_case_index
    query_tools["cwe_index"] = cwe_index

    # 获取 api_code 的 keys ，即api的函数名
    api_list = extract_api_list(api_code_file)
    # 初始化每个函数的使用次数为 0
    api_usage_count = initialize_api_usage_count(api_list)
    
    logger.info("Init FuzzingPlanner")
    plan_agent = planner.FuzzingPlanner(
        llm = llm_analyzer,
        llm_embedding = llm_embedding,
        project_name = project_name,
        api_info_file = api_summary_file, 
        api_code_file = api_code_file,
        api_call_graph_file = api_call_graph_file,
        query_tools = query_tools,
        api_usage_count = api_usage_count
    )
    

    if args.summary_api:
        logger.info("Generate API Summary")
        # 生成 api 摘要(函数摘要和文件摘要)
        plan_agent.summarize_code()
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        # api_summary/api_with_summary.json copy to api_combine/api_with_summary.json
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        # 获取函数列表
        api_list = plan_agent.extract_api_list()
    else:
        logger.info("Skip Generate API Summary")
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        api_list = plan_agent.extract_api_list()
    
    src_api_code = json.load(open(api_code_file))
    api_summary = json.load(open(api_summary_file))

    logger.info(f"Init KG Model")
    #index_pg_all_code, index_pg_api_summary, index_pg_api_code, index_pg_file_summary, summary_api_vector_index, all_src_code_vector_index, api_src_vector_index, code_base
    # 初始化知识图谱,
    # 并存储 summary_file_vector_index,api_src_vector_index,summary_api_vector_index,all_src_code_vector_index 图谱索引
    pg_all_code_index, pg_api_summary_index, pg_api_code_index, pg_file_summary_index, summary_text_vector_index, all_src_code_vector_index,api_src_vector_index, code_base = \
                        build_kg_query(
                            chromadb_dir, # 用于存放 chromaDB 向量库的文件夹
                            call_graph_csv, # API graph 的文件路径
                            all_src_api_file, # 所有源代码 API 的文件路径
                            api_summary_file, # API 摘要文件路径
                            project_name, # 项目名
                            kg_saved_folder, # 矩量图系列 index 存储路径
                            initGraphKG = True, # 是否初始化知识图谱
                            exclude_folder_list=exclude_folder_list,   # 要排除的文件夹列表
                            llm=llm_analyzer, # 用于分析代码的 LLM
                            embed_model=llm_embedding # 文本向量化的 LLM
                        )
    # 返回值为 4个语义检索索引,3个图谱索引(这里的file_summary图谱不需要),1一个元数据code_base
    '''
        pg_all_code_index	        ->  所有代码的索引
        pg_api_summary_index	    ->  API 摘要的索引
        pg_api_code_index	        ->  代码的索引
        pg_file_summary_index	    ->  文件摘要的索引
        summary_text_vector_index	->  摘要文本的向量索引
        all_src_code_vector_index	->  所有源代码的向量索引
        api_src_vector_index	    ->  源代码的向量索引
        code_base	                ->  原始代码
    '''
    # 将索引对象转换为 BaseRetriever 对象，设置 similarity_top_k=3 表示每次最多返回 3 个相似结果
    # 这些 BaseRetriever 是从不同维度（代码、摘要、文件）对输入进行检索，作为提示或上下文的一部分。
    pg_index_all_code_retriever = pg_all_code_index.as_retriever(similarity_top_k=3)
    pg_index_api_summary_retriever = pg_api_summary_index.as_retriever(similarity_top_k=3)
    pg_index_api_code_retriever = pg_api_code_index.as_retriever(similarity_top_k=3)
    pg_index_file_summary_retriever = pg_file_summary_index.as_retriever(similarity_top_k=3)

    # 初始化一个 CodeGraphRetriever,代码检索器
    # mode="HYBRID" 使用混合检索方式
    code_graph_retriever = CodeGraphRetriever(pg_index_all_code_retriever, pg_index_api_summary_retriever, pg_index_api_code_retriever, pg_index_file_summary_retriever, mode="HYBRID")
    # 将 CodeGraphRetriever 设置到 FuzzingPlanner
    plan_agent.set_code_graph_retriever(code_graph_retriever)

    logger.info("Init FuzzingGenerationAgent")
    # 初始化 FuzzingGenerationAgent,用于生成模糊测试驱动程序
    gen_agent = fuzz_generator.FuzzingGenerationAgent(
        llm_coder = llm_coder,
        llm_analyzer = llm_analyzer,
        llm_embedding = llm_embedding,
        database_dir = fuzz_projects_dir,
        headers = headers,
        query_tools = query_tools,
        language = program_language
    )
    
    logger.info(f"Init CompilationFixAgent")
    test_case_index_dir = os.path.join(fuzz_projects_dir, "test_case_index/")
    # 初始化 CompilationFixAgent,用于修复编译错误
    fix_agent = compilation_fix_agent.CompilationFixAgent(
        llm_coder=llm_coder, 
        llm_analyzer=llm_analyzer, 
        llm_embedding=llm_embedding, 
        query_tools=query_tools, 
        max_fix_itrs=5
    )

    logger.info(f"Init InputGenerationAgent")
    input_dir = os.path.join(work_dir, f"docker_shared/fuzz_driver/{project_name}/syntax_pass_rag/" )
    output_dir = os.path.join(work_dir, f"fuzzing_llm_engine/build/work/{project_name}/" ) 
    # 初始化 InputGenerationAgent,用于生成模糊测试输入
    input_agent = input_gen_agent.InputGenerationAgent(
        input_dir = input_dir,
        output_dir = output_dir,
        llm = llm_analyzer, 
        llm_embedding=llm_embedding,
        api_src=src_api_code
    )
    
    logger.info(f"Init CrashAnalyzer")
    # 初始化 CrashAnalyzer,用于分析崩溃信息
    crash_analyze_agent = crash_analyzer.CrashAnalyzer(
        llm = llm_analyzer,
        llm_embedding=llm_embedding,
        query_tools=query_tools,# 包含 test_case_index 和 cwe_index，用于检索测试用例和 CWE 信息。
        api_src=src_api_code,
        use_memory=False
    )
    
    # 初始化完成，开始组合 API
    logger.info(f"Then generation agents starts combining API")
    # 创建 Agent 结果存储的目录
    os.makedirs(agents_result_dir, exist_ok=True)
    
    # 生成模糊测试驱动
    if args.gen_driver:
    # 1. 获取组合 API 列表
        # 判断 api 文件是否存在 -> agents_results/api_combine.json
        # 存在就读取，否则从 api_list 提取 api 联合体并写入
        api_combine_file = os.path.join(agents_result_dir, "api_combine.json")
        if os.path.exists(api_combine_file):
            logger.info("Loading existing API combination from api_combine.json")
            with open(api_combine_file, 'r') as f:
                api_combine = json.load(f)
            
        else:
            logger.info("Generating new API combination")
            # LLM 生成 API 联合体
            api_combine = plan_agent.api_combination(api_list)
            with open(api_combine_file, 'w') as f:
                json.dump(api_combine, f)
    # 2. 生成 Fuzz 测试程序
        logger.info("The generation agents starts generating fuzzing driver")
        fuzz_gen_code_output_dir = os.path.join(fuzz_projects_dir, "fuzz_driver")
        os.makedirs(fuzz_gen_code_output_dir, exist_ok=True)
        gen_agent.use_memory = False
        gen_agent.driver_gen(api_combine, src_api_code, api_summary, fuzz_gen_code_output_dir,project_name) 
    else:
        logger.info("Skip Generating Fuzz Driver")
        api_combine = json.load(open(os.path.join(agents_result_dir, "api_combine.json")))
    
    # 设置生成 InputGenerationAgent 的api_combination
    input_agent.set_api_combination(api_combine)
    # 把之前生成的 fuzz_driver 复制到 work_dir/docker_shared/fuzz_driver/{project_name}/
    os.makedirs(os.path.dirname(work_dir+f"docker_shared/fuzz_driver/{project_name}/"), exist_ok=True)
    try:
        shutil.copytree(fuzz_projects_dir+"/fuzz_driver", work_dir+f"docker_shared/fuzz_driver/{project_name}/", dirs_exist_ok=True)
        logger.info(f"Copied fuzz drivers successfully.")
    except Exception as e:
        logger.error(f"Error copying fuzz drivers: {e}")
        exit()

    # 启动检查编译使用的 docker
    if not start_docker_for_check_compilation(work_dir, project_name):
        logger.info("Failed to start docker for check compilation")
        exit()
    
    # 检查编译
    if args.check_compilation:
        logger.info("Check Compilation")
        fix_agent.check_compilation(shared_dir, project_name, file_suffix=["c","cc"])
    else:
        logger.info("Skip Check Compilation")

    # 生成输入
    if args.gen_input:
        logger.info("Generate Input")
        # 遍历已经通过的 fuzz_driver 目录
        for root, dirs, files in os.walk(os.path.join(shared_dir, f"fuzz_driver/{project_name}/compilation_pass_rag/")):
            logger.info(files)
            for file in files:
                input_agent.generate_input_fuzz_driver(os.path.join(shared_dir+f"fuzz_driver/{project_name}/compilation_pass_rag/",file))
    else:
        logger.info("Skip Generate Input")  

    # 初始化 Fuzzer
    corpus_dir=os.path.join(work_dir, f"fuzzing_llm_engine/build/work/{project_name}/" )    
    coverage_dir = os.path.join(work_dir, f"fuzzing_llm_engine/build/out/{project_name}/report_target/")
    report_dir = os.path.join(fuzz_projects_dir, "coverage_report/")

    fuzzer= run_fuzzer.Fuzzer(
        directory=shared_dir, 
        project=project_name, 
        fuzz_project_dir=fuzz_projects_dir,
        corpus_dir=corpus_dir, 
        coverage_dir=coverage_dir,
        report_dir=report_dir,
        planner=plan_agent,
        compilation_fix_agent=fix_agent,
        fuzz_gen=gen_agent,
        input_gen_agent=input_agent,
        crash_analyzer=crash_analyze_agent,
        api_usage_count=api_usage_count,
        time_budget=time_budget,
        report_target_dir=report_target_dir
    )
    
    fuzzer.set_api_combination(api_combine)
    fuzzer.set_api_code(src_api_code)
    fuzzer.set_api_summary(api_summary)
    fuzzer.set_fuzz_gen_code_output_dir(os.path.join(work_dir, f"docker_shared/fuzz_driver/{project_name}/"))

    # 开始构建、fuzz
    fuzzer.build_and_fuzz()




    
    
        

