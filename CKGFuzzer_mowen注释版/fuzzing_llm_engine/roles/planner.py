import pandas as pd
import json
from llama_index.core.prompts import PromptTemplate
from loguru import logger
from pydantic import BaseModel
from typing import List
from llama_index.core.program import LLMTextCompletionProgram
from tqdm import tqdm
from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from llama_index.core import Settings
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core import get_response_synthesizer
from rag.hybrid_retriever import CodeGraphRetriever, get_query_engine  

class APICombination(BaseModel):
    api_combination: List[str]
    api_combination_reason: str

class FuzzingPlanner:
    def __init__(self, llm, llm_embedding, project_name, api_info_file, api_code_file, api_call_graph_file, query_tools,  api_usage_count, code_graph_retriever: CodeGraphRetriever = None,use_memory=False):
        self.api_call_graph_file = api_call_graph_file
        self.api_code_file = api_code_file
        self.api_info_file = api_info_file
        self.project_name = project_name
        self.llm = llm
        self.llm_embedding = llm_embedding
        self.query_tools = query_tools
        self.use_memory = use_memory
        self.api_usage_count = api_usage_count
        self.code_graph_retriever = code_graph_retriever
        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,
            embed_model=llm_embedding,
            retriever_kwargs={"similarity_top_k": 1},
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory],
        )
        self.code_summary_prompt = PromptTemplate(
            "Here is the source code information (function structure, function inputs, function return values) and the function call graph for the function named:\n"
            "{api}\n"
            "API information:\n"
            "{api_info}\n"
            "Call graph (The call graph is in CSV format, where each column represents the following attributes: 'caller', 'callee', 'caller_src', 'callee_src', 'start_body_start_line', 'start_body_end_line', 'end_body_start_line', 'end_body_end_line', 'caller_signature', 'caller_parameter_string', 'caller_return_type', 'caller_return_type_inferred', 'callee_signature', 'callee_parameter_string', 'callee_return_type', 'callee_return_type_inferred'.):\n"
            "{call_graph}\n"
            "Please generate a code summary for this function in no more than 60 words, covering the following two dimensions: code functionality and usage scenario."
        )

        self.file_summary_prompt = PromptTemplate(
            "Here is a JSON file containing all the API information from a project file:\n"
            "{file}\n"
            "with each API name followed by its code summary:\n"
            "{file_info}\n"
            "Please generate a file summary for each file in no more than 50 words, based on the code summaries of the APIs contained in each file, considering following two dimensions: file functionality and usage scenario."
            "Please translate: follow the format below: File Summary: <your summary>"
        )

        self.api_combination_query = PromptTemplate(
            "Current API usage count:\n{api_usage}\n"
            "Please provide an API combination with the following specific APIs in API usage dictionary with similar or related usage scenarios and code call relationships to this API:\n" 
            "{api}\n" 
            "The returned APIs should help achieve the highest possible code coverage when generating a fuzz driver. "
            "Prioritize APIs with lower usage counts to ensure diversity. "
            "The number of combination is limited to the maximum five APIs. "
            "Your answer should be in json format with the combination list and the reason."

        )

        self.api_combination_query_mowen = PromptTemplate(
            "Current API usage count:\n{api_usage}\n\n"
            "Please provide an API combination with the following specific API from the usage dictionary:\n{api}\n"
            "Your task:\n"
            "- Recommend up to five APIs (including the given one) that are related by usage scenarios or call relationships.\n"
            "- The combination should help achieve the highest possible code coverage in a fuzz driver.\n"
            "- Prioritize APIs with **lower usage counts** to ensure diversity.\n\n"
            "Format your response as **strict JSON** with **exactly** two keys:\n"
            "1. `combination`: a list of API names\n"
            "2. `reason`: a concise explanation for choosing these APIs\n\n"
            "Output MUST be valid JSON with no extra text, markdown, or commentary.\n\n"
            "Example:\n"
            "{\n"
            '  "combination": [\n'
            '    "ares_destroy",\n'
            '    "ares_init",\n'
            '    "ares_dup",\n'
            '    "ares_reinit",\n'
            '    "ares_init_options"\n'
            "  ],\n"
            '  "reason": "This combination covers the complete lifecycle of channel initialization, duplication, reinitialization, and destruction. The APIs are closely related through channel management operations and share common internal calls. Selecting these lower-usage-count APIs together ensures comprehensive coverage of channel state handling while maintaining diversity in the fuzz driver."\n'
            "}"
        )

        self.api_combination_query_with_memory = PromptTemplate(
            "The user is working to combine different APIs from the library based on their importance and usage scenarios.\n\n"
            "Below is the historical context:\n"
            "Start\n"
            "{memory_context}\n"
            "End\n\n"
            "Current API usage count:\n{api_usage}\n"
            "Please provide an API combination with the following specific APIs in API usage dictionary with similar or related usage scenarios and code call relationships to this API:\n" 
            "{api}\n" 
            "The returned APIs should help achieve the highest possible code coverage when generating a fuzz driver. "
            "Prioritize APIs with lower usage counts to ensure diversity. "
            "The number of combination is limited to the maximum five APIs. "
            "Your answer should be in json format with the combination list and the reason."
        )


        self.mutate_api_combination_query = PromptTemplate(
            "Current API usage count (Highest Priority):\n{api_usage}\n"
            "Low coverage APIs that need more attention (Highest Priority):\n{low_coverage_apis}\n"
            "Please provide an API combination with the following specific APIs in API usage dictionary and low coverage APIs to build fuzz driver for this API:\n" 
            "{api}\n" 
            "The returned APIs should help achieve the highest possible code coverage when generating a fuzz driver. "
            "Prioritize APIs with lower usage counts to ensure diversity."
            "Also, consider including APIs from the low coverage list to improve overall coverage. "
            "The number of combination is limited to the maximum five APIs. "
            "Please note that the previous query results for {api} were {api_combine}, which did not yield an ideal coverage when generating the Fuzz driver. The results of this query should show significant changes compared to {api_combine} and ensure the highest possible coverage. "
            "The returned APIs should help achieve the highest possible code coverage when generating a fuzz driver. "
            "Your answer should be in json format with the combination list and the reason."
        
        )


        
    def set_code_graph_retriever(self, code_graph_retriever: CodeGraphRetriever):
        self.code_graph_retriever = code_graph_retriever


    def get_code_summary(self, api_info, call_graph, api):
        logger.info("User:")
        # 格式化提示模板，将 api code(api_info) 、api graph(call_graph)、api name(api)
        logger.info(self.code_summary_prompt.format(api=api, api_info=api_info, call_graph=call_graph))
        code_response = self.llm.complete(self.code_summary_prompt.format(api=api, api_info=api_info, call_graph=call_graph)).text
        logger.info("Assistant:")
        logger.info(code_response)
        return code_response
    

    def get_file_summary(self, file_info, file):
        logger.info("User:")
        logger.info(self.file_summary_prompt.format(file_info=file_info, file=file))
        file_response = self.llm.complete(self.file_summary_prompt.format(file_info=file_info, file=file)).text
        logger.info("Assistant:")
        logger.info(file_response)
        return file_response
    

    def update_api_usage_count(self, api_list):
        for api in api_list:
            if api not in self.api_usage_count:
                self.api_usage_count[api] = 0
            self.api_usage_count[api] += 1


    def find_call_graph_with_api(self, cg_file_path, api_name):
        data = pd.read_csv(cg_file_path)
        # 定义调用图中的列名：调用者和被调用者
        column1_name = 'caller'
        column2_name = 'callee'
        value_to_find = api_name
        filtered_data = []
        # 遍历调用图数据的每一行，被调用或者被调用全部提取出来
        for index, row in data.iterrows():
            if row[column1_name] == value_to_find or row[column2_name] == value_to_find:
                filtered_data.append(row)
        return filtered_data

    def summarize_code(self):
        logger.debug(f"api_info_file -> {self.api_info_file}")
        # 载入之前聚合的 api.json code.json
        with open(self.api_info_file, 'r', encoding='utf-8') as f:
            existing_summaries = json.load(f)
        with open(self.api_code_file, 'r', encoding='utf-8') as f:
            api_code = json.load(f)
        # 遍历每个文件，为每个 api 生成 summary
        for file, apis in existing_summaries.items():
            # 最初的 api_sum 都为 ""
            for api_name, api_sum in apis.items():
                if api_sum:
                    logger.info(f"Summary for {api_name} already exists. Skipping.")
                    continue
                
                logger.info(f"Generating summary for {api_name}")
                # 找出该 api_name 在 graph 中的所有的调用关系(调用者、或者被调用者) 
                call_graph_list = self.find_call_graph_with_api(self.api_call_graph_file, api_name)   
                # Patch
                call_graph_list = call_graph_list[:50]
                # list 转为字符串
                call_graph_response = '\n'.join(' '.join(map(str, call_graph)) for call_graph in call_graph_list)
                # 加载 api 的 code
                api_info_response = api_code.get(api_name, "")
                # LLM 
                response = self.get_code_summary(api_info_response, call_graph_response, api_name)
                existing_summaries[file][api_name] = response

            if not existing_summaries[file].get("file_summary"):
                api_dict = {file: existing_summaries[file]}
                file_info_json = json.dumps(api_dict, indent=2)
                # LLM
                sum_response = self.get_file_summary(file_info_json, file)
                existing_summaries[file]["file_summary"] = sum_response

        with open(self.api_info_file, "w", encoding='utf-8') as f:
            json.dump(existing_summaries, f, indent=2, sort_keys=True, ensure_ascii=False)
        logger.info(f"API summaries have been updated in {self.api_info_file}")


    def extract_api_list(self):
        try:
            with open(self.api_code_file, 'r', encoding='utf-8') as f:
                src_api_code = json.load(f)
            
            api_list = list(src_api_code.keys())
            return api_list
        except Exception as e:
            logger.error(f"Error extracting API list from source code: {str(e)}")
            return []

    # 利用 LLM 结合代码知识图谱检索器,生成建议的 API 组合
    def api_combination(self, api_list):
        # 用于存储所有 API 的组合结果
        api_combination = []

        Settings.llm = self.llm
        Settings.embed_model = self.llm_embedding

        # 创建查询引擎   
        combine_query_engine = get_query_engine(
            self.code_graph_retriever,  # 代码图谱的检索器
            "HYBRID",                   # 混合检索模式
            self.llm, 
            get_response_synthesizer(response_mode="compact", verbose=True) # 精简回答模式
        )
        # 创建一个用于格式化 LLM 原始响应的格式化器，将其转换为结构化的 APICombination 对象
        response_format_program = LLMTextCompletionProgram.from_defaults(
            output_cls=APICombination,
            prompt_template_str="The input answer is {raw_answer}. Please reformat the answer with two key information, the API combination list and the reason.",
            llm=self.llm
        )
        # 遍历输入的 API 列表，对每个 API 生成组合建议
        for api in tqdm(api_list):
            # 构造初始问题，格式化模板中包含当前 API、完整 API 列表、使用次数统计
            # Patch 
            question = self.api_combination_query_mowen.format(
                api=api, 
                api_list=api_list, 
                api_usage=json.dumps(self.api_usage_count)
            )
            logger.info(f"API Combination, Init Question: {question}")
            logger.info(f"Use historical context: {self.use_memory}")
            # 如果使用上下文历史信息
            if self.use_memory:
                # 根据当前问题从 memory 中获取相关历史消息
                memory_chamessage = self.composable_memory.get(question)
                logger.info(f"Fetch historical context according to the init question: {memory_chamessage}")
                # 如果有历史上下文信息，则合并到问题中
                if len(memory_chamessage):
                    memory_chamessage = "\n".join([str(m) for m in memory_chamessage])
                    # 构造包含上下文的新问题
                    question = self.api_combination_query_with_memory.format(
                        api=api, 
                        memory_context=memory_chamessage, 
                        api_list=api_list,
                        api_usage=json.dumps(self.api_usage_count)
                    )
                logger.info("New question with the historical context")
                logger.info(question)
            # 调用 LLM
            response_obj = combine_query_engine.query(question)
            # 将原始响应转为结构化格式（包含 api_combination 和 reason）
            # LLM 再次处理响应格式
            '''
            PS : 这里再次调用 LLM 的时候，可能会因为回答不标准导致报错 , Pydantic 解析不匹配定义的模型结构，导致 ValidationError
                class APICombination(BaseModel):
                    api_combination: List[str]
                    api_combination_reason: str
            '''
            logger.debug(f"mowen response_obj:\n{response_obj}")
            response_format = response_format_program(raw_answer=response_obj.response)
            response = response_format.api_combination
            logger.info(f"API Combination response_obj:\n{response_obj}\n{response_format}\n{response}\n")
            # 将本轮问答保存到向量记忆中，以便后续使用历史上下文
            query_answer = [
                ChatMessage.from_str(question, "user"),
                ChatMessage.from_str(f"{response_obj.response}", "assistant"),
            ]
            self.vector_memory.put_messages(query_answer)
            # 如果响应为空，转为空列表
            if response == "Empty Response":
                response = []
            # 将当前 API 添加到组合结果中
            response.append(api)
            api_combination.append(response)
            
            # Update API usage count
            # 更新 API 使用次数记录
            self.update_api_usage_count(response)
            
        return api_combination
    
    def generate_single_api_combination(self, api, api_combine, low_coverage_apis):
        api_list = self.extract_api_list()

        Settings.llm=self.llm
        Settings.embed_model=self.llm_embedding
        
        combine_query_engine = get_query_engine(self.code_graph_retriever, "HYBRID", self.llm, \
                                                    get_response_synthesizer(response_mode="compact", verbose=True)
                                                        )

        response_format_program = LLMTextCompletionProgram.from_defaults(
            output_cls=APICombination,
            prompt_template_str="The input answer is {raw_answer}. Please reformat the answer with two key information, the API combination list and the reason.",
            llm=self.llm
        )

        question = self.mutate_api_combination_query.format(
            api=api, 
            api_combine=api_combine,
            low_coverage_apis=low_coverage_apis,
            api_usage=json.dumps(self.api_usage_count)
        )
        logger.info(f"API Combination, Init Question: {question}")
        logger.info(f"Use historical context: {self.use_memory}")
        if self.use_memory:
            memory_chamessage = self.composable_memory.get(question)
            logger.info(f"Fetch historical context according to the init question: {memory_chamessage}")
            if len(memory_chamessage):
                memory_chamessage = "\n".join([str(m) for m in memory_chamessage])
                question = self.api_combination_query_with_memory.format(
                    api=api, 
                    api_combine=api_combine,
                    low_coverage_apis=low_coverage_apis,
                    memory_context=memory_chamessage, 
                    api_usage=json.dumps(self.api_usage_count)
                )
            logger.info("New question with the historical context")
            logger.info(question)

        response_obj = combine_query_engine.query(question)
        response_format = response_format_program(raw_answer=response_obj.response)
        response = response_format.api_combination
        logger.info(f"API Combination Response:{response_obj} {response_format}")

        query_answer = [
            ChatMessage.from_str(question, "user"),
            ChatMessage.from_str(f"{response_obj.response}", "assistant"),
        ]
        self.vector_memory.put_messages(query_answer)

        if response == "Empty Response":
            response = []
        response.append(api)

        return response
    

   
