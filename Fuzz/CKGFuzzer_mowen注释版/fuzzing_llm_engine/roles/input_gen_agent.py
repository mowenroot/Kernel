import os
# # Get the current working directory
# current_work_dir = os.getcwd()
# print("=================")
# print(current_work_dir)

import time
import shutil
from pydantic import BaseModel
import re
from llama_index.core.prompts import PromptTemplate
from loguru import logger
from llama_index.core.program import LLMTextCompletionProgram

from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
# from models.baseLLM import BaseLLM
import hashlib
import time
import zipfile

from . import static_analysis_agent

def generate_hash(file_name):
    # Get the current time
    current_time = time.time()
    
    # Combine the current time and the file name
    combined_string = f"{file_name}_{current_time}"
    
    # Generate a hash using SHA-256
    hash_object = hashlib.sha256(combined_string.encode())
    hash_code = hash_object.hexdigest()
    
    return hash_code

class InputSeed(BaseModel):
    input_seed: str
    explanation: str = ""
    
class InputGenerationAgent:
    generate_input_prompt = PromptTemplate(
        "You are an expert fuzzer tasked with generating high-coverage inputs for a fuzz driver. Analyze the following:\n"
        "1. Fuzz Driver Program:\n{source_code}\n"
        "2. Data Flow Graph:\n{dfg}\n"
        "3. API Function Signatures:\n{api_signature}\n"
        "Generate a fuzz input seed that:\n"
        "- Maximizes code coverage\n"
        "- Targets edge cases and boundary conditions\n"
        "- Adheres to input requirements in the API signatures\n"
        "- Explores different execution paths\n"
        "Provide only the input seed as a string, not a complete program."
    )
    
    generate_input_prompt_with_memory = PromptTemplate(
        "You are an expert fuzzer tasked with generating high-coverage inputs for a fuzz driver. Analyze the following:\n"
        "1. Fuzz Driver Program:\n{source_code}\n"
        "2. Data Flow Graph:\n{dfg}\n"
        "3. API Function Signatures:\n{api_signature}\n"
        "Generate a fuzz input seed that:\n"
        "- Maximizes code coverage\n"
        "- Targets edge cases and boundary conditions\n"
        "- Adheres to input requirements in the API signatures\n"
        "- Explores different execution paths\n"
        "Provide only the input seed as a string, not a complete program."
        "Below is the historical context:\n"
        "Start\n"
        "{memory_context}\n"
        "End\n\n"
    )
        
    def __init__(self,input_dir,output_dir, llm, llm_embedding, api_src, api_combine=None, use_memory:bool=False):
        self.input_dir=input_dir
        self.output_dir=output_dir
        self.llm=llm
        self.api_src=api_src
        self.api_combine=api_combine
        self.static_analyzer = static_analysis_agent.StaticAnalysisAgent(
            llm=llm,
            llm_embedding=llm_embedding
            )
        # self.api_combine=api_combine
        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,  # leave as None to use default in-memory vector store
            embed_model=llm_embedding,
            # llm = llm_analyzer,
            retriever_kwargs={"similarity_top_k": 1},
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory],
        )
        self.use_memory = use_memory
        self.input_seed_generator = LLMTextCompletionProgram.from_defaults(
            output_cls=InputSeed,
            prompt_template_str="The raw input answer is {raw_input_seed}. Please reformat the answer with two key information, the input seed and the reason. If there is no reason, leave it with the empty str. Output the result in valid JSON format.",
            llm=self.llm,
            verbose=True 
        )

    def set_api_combination(self, api_combine):
        self.api_combine = api_combine
     
    # 根据源码、静态分析数据流图（DFG）和相关 API 生成用于 Fuzz 的输入种子
    def generate_input(self, source_code, api_combination_index):
        # LLM 对源代码进行数据流图(DFG),得到代码的数据依赖结构
        dfg = self.static_analyzer.dfg_analysis(source_code)
        # 通过文件 ID 定位 api 联合体
        api_list = self.api_combine[api_combination_index-1]

        api_signature = ""

        for api in api_list:
            if api in self.api_src.keys():
                # 提取 API 的函数签名
                api_signature_single = f"{api}:\n{self.extract_function_signature(self.api_src[api])}"
                api_signature = "\n".join([api_signature,api_signature_single])
            else:
                continue
        logger.info(f"api_signature:\n{api_signature}")
        # prompt format
        question = self.generate_input_prompt.format(dfg=dfg,source_code=source_code,api_signature=api_signature)
        if self.use_memory:
            memory_context = self.composable_memory.get(question)
            question = self.generate_input_prompt_with_memory.format(dfg=dfg, memory_context=memory_context,source_code=source_code,api_signature=api_signature)
        # LLM 生成输入种子
        raw_input_seed = self.llm.complete(question).text
        logger.info(f"raw_input_seed:\n{raw_input_seed}")
        try:
            # llm 格式化为 ： 输入种子和原因
            input_seed = self.input_seed_generator(raw_input_seed=raw_input_seed)
        except Exception as e:
            # 如果失败则用原始输入
            input_seed = InputSeed(input_seed=raw_input_seed, explanation=str(e))
        question = self.generate_input_prompt.format(dfg=dfg,source_code=source_code,api_signature=api_signature)
        msgs =[
            ChatMessage.from_str(question, "user"),
            ChatMessage.from_str(raw_input_seed, "assistant")
        ]
        self.composable_memory.put_messages(msgs)
        # pattern = r'```(.*?)```'
        # match = re.search(pattern, input_seed, re.DOTALL)
        # if match:
        #     input_seed=match.group(1)
        # else:
        #     input_seed="None"
        logger.info(f"input_seed:\n{input_seed.input_seed}")
        return input_seed.input_seed  

    # 从文件名中提取数字 ID ： driver_12.cpp -> 12
    def extract_number_from_filename(self, filename):
        # Define the regex pattern to match the number before .c or .cc
        pattern = r'_(\d+)\.(c|cc)$'
        
        # Search the pattern in the filename
        match = re.search(pattern, filename)
        
        # If a match is found, return the number as an integer
        if match:
            return int(match.group(1))
        else:
            return None

    def extract_function_signature(self,code):

        # 正则表达式 -> 用于匹配以合法函数签名开头的行
        #  ^[a-zA-Z_][a-zA-Z0-9_ \*]* ：匹配返回类型（如 int、char *、void 等），包括指针符号 *
        #  \([^\)]*\) ：匹配参数列表（如 (int x, char *y)）
        #  \s*\{ ：匹配左大括号前可能存在的空格，用于定位函数体的开始（但不包含函数体）
        pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_ \*]*\([^\)]*\)\s*\{', re.MULTILINE)
            
        matches = pattern.findall(code)
        # 去掉每个匹配项末尾的 { 并去除多余空白
        signatures = [match[:-1].strip() for match in matches]

        return signatures
                

    def clear_corpus_folder(self, file_path):

        file_name = os.path.basename(file_path)
        fuzzer_name = os.path.splitext(file_name)[0]
        corpus_folder = os.path.join(self.output_dir, f"{fuzzer_name}_corpus")
        
        if os.path.exists(corpus_folder):
            for item in os.listdir(corpus_folder):
                item_path = os.path.join(corpus_folder, item)
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            logger.info(f"Cleared corpus folder for {fuzzer_name}")
        else:
            logger.info(f"Corpus folder for {fuzzer_name} does not exist")
            
    # 读取源码文件,生成一个用于 fuzz 测试的初始输入 seed,并将其保存到指定目录中
    def generate_input_fuzz_driver(self, file_path):

        with open(file_path, 'r', encoding='utf-8') as f:
            # 读取源码文件
            source_code = f.read()
            # 从文件名中提取数字 ID ： driver_12.cpp -> 12
            file_id = self.extract_number_from_filename(file_path)
            # 根据源代码和提取的 ID 生成一个 fuzz 测试初始输入种子
            input_seed = self.generate_input(source_code, file_id)
            logger.info(f"{file_path} Generate Input seed: {input_seed}")
            # 路径 /path/mowen.cpp
            #    → file_name = mowen.cpp
            #       → fuzzer_name = mowen
            file_name = os.path.basename(file_path)
            fuzzer_name = os.path.splitext(file_name)[0]
            logger.info(f"================ {fuzzer_name}")
            # 创建一个用于保存 corpus 的文件夹
            corpus_folder = os.path.join(self.output_dir, f"{fuzzer_name}_corpus")
            os.makedirs(corpus_folder, exist_ok=True)
            # 生成 hash,并对该文件写入种子
            hash_code_file = generate_hash(f"{fuzzer_name}_corpus.txt")
            logger.info(f"Save -> {corpus_folder}->{hash_code_file}.txt")
            with open(os.path.join(corpus_folder, f"{hash_code_file}.txt"), 'w', encoding='utf-8') as f:
                f.write(input_seed)

            
            
        
