from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.openai_like import OpenAILike
from llama_index.core.prompts import PromptTemplate
from llama_index.core import Settings
from llama_index.core import StorageContext, load_index_from_storage, get_response_synthesizer,Document
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.postprocessor import SimilarityPostprocessor
# from models.llamindex_api import LLamaIndexOpenAIModel
from configs.llm_config import LLMConfig
# from models.baseLLM import BaseLLM
import os
from utils.check_gen_fuzzer import run
from loguru import logger
import shutil
import re
from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from llama_index.core import Settings


def extract_code(s):
    # 使用正则表达式匹配格式
    pattern = r'```(?:c|cpp|c\+\+)\s(.*?)```'
    match = re.search(pattern, s, re.DOTALL)  # re.DOTALL允许点(.)匹配包括换行符在内的所有字符
    if match:
        # 返回匹配到的代码部分
        return match.group(1)
    else:
        return "No code found"
    
class CompilationFixAgent:
    fix_compilation_prompt = PromptTemplate(
        "You are an expert C/C++ programmer specializing in fixing compilation errors. Your task is to fix the following fuzz driver file:\n"
        "```\n"
        "{fuzz_driver}\n"
        "```\n"
        "Compilation errors:\n"
        "{error}\n"
        "Correct function call example (if available):\n"
        "{example}\n"
        "Instructions:\n"
        "1. Analyze the errors carefully.\n"
        "2. Make minimal necessary changes to fix the compilation issues.\n"
        "3. Do not modify or remove any #include statements.\n"
        "4. Ensure the fixes address all reported errors.\n"
        "5. If adding new functions or variables, make sure they are properly declared and used.\n"
        "6. Double-check that your changes don't introduce new errors.\n"
        "7. Return only the complete, fixed code wrapped in triple backticks (```).\n"
        "8. Add brief comments explaining your changes.\n"
        "Fix the code now:"
    )
    
    fix_compilation_prompt_with_memory = PromptTemplate(
        "You are an expert C/C++ programmer specializing in fixing compilation errors. Your task is to fix the following fuzz driver file:\n"
        "```\n"
        "{fuzz_driver}\n"
        "```\n"
        "Compilation errors:\n"
        "{error}\n"
        "Correct function call example (if available):\n"
        "{example}\n"
        "Instructions:\n"
        "1. Analyze the errors carefully.\n"
        "2. Make minimal necessary changes to fix the compilation issues.\n"
        "3. Do not modify or remove any #include statements.\n"
        "4. Ensure the fixes address all reported errors.\n"
        "5. If adding new functions or variables, make sure they are properly declared and used.\n"
        "6. Double-check that your changes don't introduce new errors.\n"
        "7. Return only the complete, fixed code wrapped in triple backticks (```).\n"
        "8. Add brief comments explaining your changes.\n"
        "Fix the code now:"
        "You are a software repair expert. You need fix one fuzz driver with some compilation errors.\n"
        "Below is the historical context (ignore if empty):\n"
        "Start\n"
        "{context_memory}\n"
        "End\n"
    )


    fix_compilation_query = PromptTemplate(
        "You are a software repair expert. This is a fuzz driver file:\n"
         "```\n"
        "{fuzz_driver}\n"
        "```\n"
        "These are the error messages from the compilation check:\n"
        "{error}\n"
        "Please return the code snippets for all functions mentioned in the error messages."
    )
    
    summarize_errors_prompt = PromptTemplate(
        "You are an expert in C/C++ compilation errors. Your task is to summarize the following compilation error message:\n"
        "```\n"
        "{error_message}\n"
        "```\n"
        "Instructions:\n"
        "1. Identify the most common or critical error types.\n"
        "2. Provide a brief summary of up to 5 main issues.\n"
        "3. Keep your summary concise, ideally within 3-5 lines.\n"
        "Please provide the summary now:"
    )
    
    
    def __init__(self, llm_coder, llm_analyzer, llm_embedding, query_tools, use_memory: bool = False, max_fix_itrs=5):
        
        self.llm_coder = llm_coder #LLamaIndexOpenAIModel("deepseek-coder", llm_coder_config)

        self.llm_analyzer = llm_analyzer #LLamaIndexOpenAIModel("deepseek-chat", llm_analyzer_config)
        self.llm_embedding = llm_embedding
        self.driver_index = query_tools["test_case_index"]
    
        Settings.llm= self.llm_analyzer
        Settings.embed_model= self.llm_embedding

        self.driver_retriever = self.driver_index.as_retriever(similarity_top_k=3, search_type="similarity")
        self.driver_query_engine = RetrieverQueryEngine.from_args(
                    llm= self.llm_analyzer if self.llm_analyzer else Settings.llm,
                    retriever=self.driver_retriever,
                    node_postprocessors=[SimilarityPostprocessor(similarity_cutoff=0.7)],
                    response_synthesizer=get_response_synthesizer(response_mode="compact", verbose=True),
                    verbose=True
        )   
        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm_analyzer)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,  # leave as None to use default in-memory vector store
            embed_model=llm_embedding,
            # llm = llm_analyzer,
            retriever_kwargs={"similarity_top_k": 1}
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory],
        )
        self.use_memory = use_memory
        self.max_fix_itrs = max_fix_itrs

    def update_external_base(self, code):
        '''
        将新的代码文档添加到已有的索引中;
        基于更新后的索引构建语义检索器;
        用检索器和大语言模型组合成一个问答引擎(RetrieverQueryEngine)
        返回这个引擎供调用。
        '''
        code_doc = Document(text=code)
        # 将代码索引插入到 driver_index
        self.driver_index.insert(code_doc)
        # 创建一个检索器, 3个片段 ,similarity -> 语义相似度的搜索方式
        self.driver_retriever = self.driver_index.as_retriever(similarity_top_k=3, search_type="similarity")
        #语义问答引擎 driver_query_engine
        
        self.driver_query_engine = RetrieverQueryEngine.from_args(
                    llm= self.llm_analyzer if self.llm_analyzer else Settings.llm,
                    retriever=self.driver_retriever,
                    node_postprocessors=[SimilarityPostprocessor(similarity_cutoff=0.7)],# 只有相似度大于等于 0.7 的文档才参与最终生成。
                    response_synthesizer=get_response_synthesizer(response_mode="compact", verbose=True),# compact-> 生成尽量简洁的回答
                    verbose=True
        )
        return self.driver_query_engine

    def count_errors(self, error_message):
        return error_message.count("error:")
    

    def summarize_errors(self, error_message, max_errors=6):
        error_count = self.count_errors(error_message)
        
        if error_count < max_errors or len(error_message) < 1000:
            return error_message
        else:
            question = self.summarize_errors_prompt.format(error_message=error_message)
            summary = self.llm_analyzer.complete(question).text
            return f"There are {error_count} compilation errors. Summary:\n{summary}"
    
    # 自动修复代码编译错误
    def fix_compilation(self, error, code):       
        # LLM 提取错误信息对应的代码片段
        summarized_error = self.summarize_errors(error)
        # LLM 给出修复样例
        try:
            retrieve_example_question = self.fix_compilation_query.format(fuzz_driver=code, error=summarized_error)
            example = self.driver_query_engine.query(retrieve_example_question)
        except:
            # Fallback to using original error if query fails
            # 如果使用提取错误信息失败，则使用原始的错误信息
            retrieve_example_question = self.fix_compilation_query.format(fuzz_driver=code, error=error)
            example = self.driver_query_engine.query(retrieve_example_question)
        # prompt 设置
        question = self.fix_compilation_prompt.format(fuzz_driver=code, error=error, example=example)
        if self.use_memory:
            if len(self.composable_memory.get_all()) != 0:
                context_memory = self.composable_memory.get(self.fix_compilation_query.format(fuzz_driver=code, error=summarized_error))
                question = self.fix_compilation_prompt_with_memory.format(fuzz_driver=code, context_memory=context_memory, error=error, example=example) 
        logger.info(f"Use model {self.llm_coder.model} to fix code")
        logger.info(f"Question: {question}")
        # LLM 生成修复代码
        fix_code = self.llm_coder.complete(question).text
        msgs = [
            ChatMessage.from_str(question, "user"),
            ChatMessage.from_str(fix_code, "assistant")
        ]
        logger.info(f"Code: {fix_code}")
        self.composable_memory.put_messages(msgs)
        return fix_code


    # 用于检查指定目录下 fuzz 驱动文件的编译情况，并在必要时自动尝试修复
    def check_compilation(self, directory, project, file_suffix):
        # 编译通过的目录 -> compilation_pass_rag
        if not os.path.exists(directory+f"fuzz_driver/{project}/compilation_pass_rag/"):
            os.makedirs(directory+f"fuzz_driver/{project}/compilation_pass_rag/")
        logger.info(directory+f"fuzz_driver/{project}/")
        # 临时目录 fix_tmp 存放待检查和修复的 fuzz 驱动文件
        fix_tmp = os.path.join(directory, f"fuzz_driver/{project}/")
        os.makedirs(fix_tmp, exist_ok=True)
        # 获取项目 fuzz 驱动目录下所有的文件(不递归)
        all_items = os.listdir(directory + f"fuzz_driver/{project}/")
        files = [item for item in all_items if os.path.isfile(os.path.join(directory, f"fuzz_driver/{project}/", item))]
        # files 为所有待测试编译的文件
        logger.info(files)
    
        for file in files:
            # 跳过 fix 文件
            if file.startswith("fix"):
                continue
            logger.info(file)
            # 加载 fuzz 驱动文件
            with open(directory+f"fuzz_driver/{project}/"+file,"r") as fr:
                code=fr.read()
            # 获取文件后缀
            f_suffix = file.split(".")[-1]
            if f_suffix in file_suffix:  # Modify this to match your desired file types      
                run_args = ["check_compilation", project, "--fuzz_driver_file", file]
                # 利用 check_gen_fuzzer.py 
                result =  run(run_args)            
            logger.info(f"check_compilation {file}, result:\n {result}")
            if "error:" not in result:
                # 如果编译没有任何错误
                logger.info('Compilation check pass.')
                # 拷贝 fuzz 文件到 compilation_pass_rag 目录下 
                shutil.copy(directory+f"fuzz_driver/{project}/"+file, directory+f"fuzz_driver/{project}/compilation_pass_rag/")
                # Remove the corresponding .o file if it exists
                # 删除编译的 .o 文件
                base_name = os.path.splitext(file)[0]
                object_file = f"{base_name}.o"
                object_file_path = os.path.join(directory, f"fuzz_driver/{project}/", object_file)
                if os.path.exists(object_file_path):
                    os.remove(object_file_path)
                    logger.info(f"Removed object file: {object_file_path}")
                self.update_external_base(code)
            else:
                # 编译有报错情况
                i=1
                # 最多处理 5 次
                while i<=self.max_fix_itrs:      
                    logger.warning(f'compilation errors -> {file} has {i} ')
                    # LLM 生成修复代码
                    fxi_code_raw = self.fix_compilation(error=result,code=code)   
                    input(f"{logger.debug('mowen')}")     
                    # 提权 Markdown 中的代码
                    fix_code = extract_code(fxi_code_raw)
                    if fix_code == "No code found":
                        logger.info(fxi_code_raw)
                        i = self.max_fix_itrs + 1
                        continue
                    code = fix_code
                    fixed_file_name = f"fix_{file}"
                    # 写入到文件中( fix_  )
                    with open(f"{fix_tmp}/{fixed_file_name}","w") as fw:
                        logger.info("save fixed file:")
                        logger.info(directory+f"fuzz_driver/{project}/{fixed_file_name}")
                        logger.info(fix_code)
                        fw.write(fix_code) 
                        # logger.info("Done Write")
                    # 再次编译测试
                    run_args = ["check_compilation", project, "--fuzz_driver_file", fixed_file_name]
                    result =  run(run_args)
                    msg =[
                        ChatMessage.from_str(result, "user")
                    ]
                    logger.info(f"After fixing, the fixed code checking result is \n: {result}")
                    self.composable_memory.put_messages(msg)
                    if "error:" not in result:
                        # fix 后的代码编译成功
                        # pdb.set_trace()
                        logger.info('Compilation check pass.')
                        shutil.copy(f"{fix_tmp}/{fixed_file_name}", directory+f"fuzz_driver/{project}/compilation_pass_rag/")
                        base_name = os.path.splitext(fixed_file_name)[0]
                        object_file = f"{base_name}.o"
                        object_file_path = os.path.join(directory, f"fuzz_driver/{project}/", object_file)
                        if os.path.exists(object_file_path):
                            os.remove(object_file_path)
                            logger.info(f"Removed object file: {object_file_path}")
                        self.update_external_base(code)
                        os.remove(directory+f"fuzz_driver/{project}/{fixed_file_name}")
                        break
                    os.remove(directory+f"fuzz_driver/{project}/{fixed_file_name}")
                    # 最后都会删除生成的 fix 文件
                    i+=1

    def single_fix_compilation(self,file_name,dir,project):
        with open(dir+file_name,"r") as fr:
            code=fr.read()     
        run_args = ["check_compilation", project, "--fuzz_driver_file", file_name]
        result =  run(run_args)                  
        logger.info(f"check_compilation for new fuzz driver {file_name}, result:\n {result}")
        if "error:" not in result:
            logger.info('Compilation check pass.')
            shutil.copy(f"{dir}/{file_name}", dir+"compilation_pass_rag/")
            base_name = os.path.splitext(file_name)[0]
            object_file = f"{base_name}.o"
            object_file_path = os.path.join(dir, object_file)
            if os.path.exists(object_file_path):
                os.remove(object_file_path)
                logger.info(f"Removed object file: {object_file_path}")
            self.update_external_base(code)
            return True
        else:
            i=1
            if file_name.startswith("fix_"):
                file_name = file_name[4:]
            while i<=self.max_fix_itrs:     
                fix_code_raw = self.fix_compilation(error=result,code=code)   
                fix_code = extract_code(fix_code_raw)
                if fix_code == "No code found":
                    logger.info(fix_code_raw)
                    i = self.max_fix_itrs + 1
                    continue
                code = fix_code
                fixed_file_name = f"fix_{file_name}"
                with open(f"{dir}/{fixed_file_name}","w") as fw:
                    logger.info("save fixed file:")
                    logger.info(dir)
                    logger.info(fix_code)
                    fw.write(fix_code) 
                    # logger.info("Done Write")
                run_args = ["check_compilation", project, "--fuzz_driver_file", fixed_file_name]
                result =  run(run_args)
                msg =[
                    ChatMessage.from_str(result, "user")
                ]
                logger.info(f"After fixing, the fixed code checking result is \n: {result}")
                self.composable_memory.put_messages(msg)
                if "error:" not in result:
                    # pdb.set_trace()
                    logger.info('Compilation check pass.')
                    shutil.copy(f"{dir}/{fixed_file_name}", dir+"compilation_pass_rag/")
                    base_name = os.path.splitext(fixed_file_name)[0]
                    object_file = f"{base_name}.o"
                    object_file_path = os.path.join(dir, object_file)
                    if os.path.exists(object_file_path):
                        os.remove(object_file_path)
                        logger.info(f"Removed object file: {object_file_path}")
                    self.update_external_base(code)
                    os.remove(f"{dir}/{fixed_file_name}")
                    return True
                os.remove(f"{dir}/{fixed_file_name}")
                i+=1
            logger.info(f"Failed to fix compilation after {self.max_fix_itrs} attempts.")
            return False
        