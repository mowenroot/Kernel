import sys
from pathlib import Path
import os
import re
from loguru import logger
from llama_index.core.prompts import PromptTemplate
from llama_index.core import Settings
from llama_index.core  import  ServiceContext
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.postprocessor import SimilarityPostprocessor
from llama_index.core import get_response_synthesizer
from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from llama_index.core.program import LLMTextCompletionProgram
from pydantic import BaseModel
from typing import List, Optional



class CrashAnalysis(BaseModel):
    is_api_bug: bool
    crash_category: str


class CrashAnalyzer:
    init_crash = ["Segment Violation", "Uninitialized Stack", "Integer Overflow", "Buffer Overflow", "Out of Memory", "Null Pointer Dereference", "Memory Leak", "File Descriptor Leak", "Misaligned Address", "Type Error Cast", "TimeOut", "Assertion Failure"]

    crash_analyze_prompt = PromptTemplate(
     """You are a software analysis expert tasked with analyzing the root cause of a crash during fuzzing. You will be provided with the following information:

    1. Crash information from fuzz engine
    2. Source code of the crashing fuzz driver
    3. Source code of the project APIs used by the fuzz driver
    4. Potential error patterns extracted from both the fuzz driver and the API source code
    5. Related CWE vulnerabilities

    Crash information:
    {crash_info}

    Fuzz driver source code:
    {fuzz_driver}

    Fuzzed API source code:
    {api_info}

    Potential error patterns in fuzz driver:
    {fuzz_driver_error_patterns}

    Potential error patterns in API:
    {api_error_patterns}

    Related CWE vulnerabilities:
    {related_cwe_vulnerabilities}

    Based on this information, please determine whether the crash was caused by the fuzz driver code or by a bug in the project's API. Provide a comprehensive analysis including:

    1. Is this an API bug? (Return True if it's an API bug, False if it's a fuzz driver bug)
    2. The specific location in the code where the crash likely occurred
    3. Description of the variables involved in the crash
    4. Which potential error patterns are relevant to this crash
    5. Any violations of expected behavior based on your understanding of the code
    6. Which CWE vulnerabilities (if any) are relevant to this crash
    7. A detailed explanation of your reasoning
    8. Categorize the crash into one of the following categories: {init_crash}. If the crash doesn't fit into any of these categories, suggest a new category and explain why it's needed.

    If you believe the crash was caused by the fuzz driver:
    - Provide the relevant fuzz driver code snippet
    - Explain how the fuzz driver might be misusing the API

    If you believe the crash was caused by a bug in the project's API:
    - Provide the relevant API code snippet
    - Explain how the API might be failing to handle certain inputs or conditions

    Please structure your response to clearly address each of these points."""
    )

    crash_analyze_prompt_with_memory = PromptTemplate(
     """You are a software analysis expert tasked with analyzing the root cause of a crash during fuzzing. You will be provided with the following information:

    1. Crash information from fuzz engine
    2. Source code of the crashing fuzz driver
    3. Source code of the project APIs used by the fuzz driver
    4. Potential error patterns extracted from both the fuzz driver and the API source code
    5. Related CWE vulnerabilities

    Crash information:
    {crash_info}

    Fuzz driver source code:
    {fuzz_driver}

    Fuzzed API source code:
    {api_info}

    Potential error patterns in fuzz driver:
    {fuzz_driver_error_patterns}

    Potential error patterns in API:
    {api_error_patterns}

    Related CWE vulnerabilities:
    {related_cwe_vulnerabilities}

    Based on this information, please determine whether the crash was caused by the fuzz driver code or by a bug in the project's API. Provide a comprehensive analysis including:

    1. Is this an API bug? (Return True if it's an API bug, False if it's a fuzz driver bug)
    2. The specific location in the code where the crash likely occurred
    3. Description of the variables involved in the crash
    4. Which potential error patterns are relevant to this crash
    5. Any violations of expected behavior based on your understanding of the code
    6. Which CWE vulnerabilities (if any) are relevant to this crash
    7. A detailed explanation of your reasoning
    8. Categorize the crash into one of the following categories: {init_crash}. If the crash doesn't fit into any of these categories, suggest a new category and explain why it's needed.

    If you believe the crash was caused by the fuzz driver:
    - Provide the relevant fuzz driver code snippet
    - Explain how the fuzz driver might be misusing the API

    If you believe the crash was caused by a bug in the project's API:
    - Provide the relevant API code snippet
    - Explain how the API might be failing to handle certain inputs or conditions

    Please structure your response to clearly address each of these points."""
    
    "Below is the historical context:\n"
    "Start\n"
    "{memory_context}\n"
    "End\n\n"
    )


    def __init__(self, llm, llm_embedding, query_tools, api_src, use_memory=False):

        self.llm = llm
        self.llm_embedding = llm_embedding
        self.api_src = api_src
        self.query_tools = query_tools
        self.use_memory = use_memory
        self.init_crash = CrashAnalyzer.init_crash

        # Initialize memory components
        self.chat_memory_buffer = ChatMemoryBuffer.from_defaults(llm=llm)
        self.vector_memory = VectorMemory.from_defaults(
            vector_store=None,  # leave as None to use default in-memory vector store
            embed_model=llm_embedding,
            retriever_kwargs={"similarity_top_k": 1}
        )
        self.composable_memory = SimpleComposableMemory.from_defaults(
            primary_memory=self.chat_memory_buffer,
            secondary_memory_sources=[self.vector_memory]
        )

    def extract_potential_error_patterns(self, code):
        prompt = PromptTemplate(
            "Analyze the following code and identify potential error patterns or edge cases that could lead to crashes:\n\n{code}\n\nList the potential error patterns (Without any summary or advice for fixing the bugs):"
        )
        response = self.llm.complete(prompt.format(code=code))
        return response.text.split('\n')


    def query_cwe_vulnerabilities(self, crash_info):
        cwe_index = self.query_tools["cwe_index"]

        # Summarize crash_info if it's too long
        if len(crash_info) > 3000:  # Adjust this threshold as needed
            summarize_prompt = PromptTemplate(
                "Summarize the following crash information, focusing on the key details that might be relevant to identifying CWE vulnerabilities:\n\n{crash_info}\n\nSummary:"
            )
            crash_info_summary = self.llm.complete(summarize_prompt.format(crash_info=crash_info)).text
        else:
            crash_info_summary = crash_info

        cwe_query = PromptTemplate(
            "Analyze the following crash information for potential CWE vulnerabilities:\n"
            "Crash information:\n{crash_info}\n\n"
            "Identify and list the most relevant CWE vulnerabilities that might be related to this crash."
        )
        Settings.llm = self.llm
        Settings.embed_model = self.llm_embedding

        question = cwe_query.format(crash_info=crash_info_summary)
        
        cwe_retriever = cwe_index.as_retriever(similarity_top_k=3)
        cwe_query_engine = RetrieverQueryEngine.from_args(
            retriever=cwe_retriever,
            node_postprocessors=[SimilarityPostprocessor(similarity_cutoff=0.7)],
            response_synthesizer=get_response_synthesizer(
                response_mode="compact",
                verbose=True
            ),
            verbose=True
        )
        
        cwe_response = cwe_query_engine.query(question)
        return cwe_response.response
    

    def analyze_crash(self, crash_info, fuzz_driver_path, api_combine):
        with open(fuzz_driver_path, 'r') as file:
            fuzz_driver = file.read()
        
        api_info = ""
        for api in api_combine:
            
            if api in self.api_src:
                api_info += f"{api}:\n{self.api_src[api]}\n\n"
            else:
                api_info += f"{api}: Source code not available\n\n"
        
        fuzz_driver_error_patterns = self.extract_potential_error_patterns(fuzz_driver)
        api_error_patterns = self.extract_potential_error_patterns(api_info)

        related_cwe_vulnerabilities = self.query_cwe_vulnerabilities(crash_info)
        
        question = self.crash_analyze_prompt.format(
            crash_info=crash_info,
            fuzz_driver=fuzz_driver,
            api_info=api_info,
            fuzz_driver_error_patterns="\n".join(fuzz_driver_error_patterns),
            api_error_patterns="\n".join(api_error_patterns),
            related_cwe_vulnerabilities=related_cwe_vulnerabilities,
            init_crash=", ".join(self.init_crash)
        )
        
        logger.info("Crash Analysis Question:")
        logger.info(question)

        response = self.llm.complete(question).text
        
        logger.info("Crash Analysis Response:")
        logger.info(response)

        response_format_program = LLMTextCompletionProgram.from_defaults(
            output_cls=CrashAnalysis,
            prompt_template_str=(
                "The input answer is:\n {raw_answer}\n. "
                "Please help me extract the bool value of the variable <is_api_bug> and the string value of <crash_category>.\n"
                "If a new crash category was suggested, include it in <crash_category>."
            ),
            llm=self.llm
        )
        analyze = response_format_program(raw_answer=response)
        is_api_bug = analyze.is_api_bug
        crash_category = analyze.crash_category

        # Update init_crash if a new category was suggested
        if crash_category not in self.init_crash:
            self.init_crash.append(crash_category)
            logger.info(f"New crash category added: {crash_category}")

        if self.use_memory:
            query_answer = [
                ChatMessage.from_str(question, "user"),
                ChatMessage.from_str(response, "assistant"),
            ]
            self.composable_memory.put_messages(query_answer)
        
        return is_api_bug, crash_category, response
        
        