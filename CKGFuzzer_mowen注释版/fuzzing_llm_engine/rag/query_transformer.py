#  "You are an expert at world knowledge. You are given a programming problem. Your task is to step back and paraphrase a question to a more generic step-back question, which is easier to answer. Here are a few examples: \n"
# "Original Question: {exmpale_org_1}\n" 
# "Stepback Question: {exmpale_step_1}\n"
# "Original Question: {exmpale_org_2}\n" 
# "Stepback Question: {exmpale_step_2}\n"
# "Original Question: {org_query}\n"
# "Stepback Question:"
# https://arxiv.org/pdf/2310.06117#page=14.34   
from typing import Dict, Optional
from llama_index.legacy.prompts.base import PromptTemplate
from llama_index.legacy.indices.query.query_transform.base import BaseQueryTransform
from llama_index.legacy.llm_predictor.base import LLMPredictorType
from llama_index.legacy.llms.utils import resolve_llm
from llama_index.legacy.prompts.mixin import PromptDictType
from llama_index.legacy.utils import print_text


STEP_BACK_PROMPT = (
    "You are an expert at software programming and security. You are given a programming problem. Your task is to extract programming concepts and principles involved in solving the problem, which is easier to answer. Here are a few examples: \n"
    "Original Question: How do you implement operator overloading in C++ to handle arithmetic operations for a custom data type?\n" 
    "Stepback Question: What are the principles of operator overloading in C++, and how can it be used to extend the functionality of user-defined types?\n"
    "Original Question: How can you use templates in C++ to implement a generic stack data structure?\n" 
    "Stepback Question: What is generic programming in C++, and how do templates facilitate code reusability and type safety?\n"
    "Original Question: How do you manage memory allocation and deallocation in C++ to prevent memory leaks?\n" 
    "Stepback Question: What are the best practices for memory management in C++, and how do they help in avoiding common memory-related issues??\n"
    "Original Question: {org_query}\n"
    "Stepback Question:"
)
STEP_BACK_PROMPT_TEMPLATE = PromptTemplate( STEP_BACK_PROMPT )

class StepBackTransform(BaseQueryTransform):
    """Step decompose query transform.

    Decomposes query into a subquery given the current index struct
    and previous reasoning.

    NOTE: doesn't work yet.

    Args:
        llm_predictor (Optional[LLM]): LLM for generating
            hypothetical documents

    """

    def __init__(
        self,
        llm: Optional[LLMPredictorType] = None,
        step_back_query_prompt: Optional[PromptTemplate] = None,
        verbose: bool = False,
    ) -> None:
        """Init params."""
        super().__init__()
        self._llm = llm or resolve_llm("default")
        self._step_back_query_prompt = (
            step_back_query_prompt or STEP_BACK_PROMPT_TEMPLATE
        )
        self.verbose = verbose

    def _get_prompts(self) -> PromptDictType:
        """Get prompts."""
        return {"step_decompose_query_prompt": self._step_back_query_prompt}

    def _update_prompts(self, prompts: PromptDictType) -> None:
        """Update prompts."""
        if "step_decompose_query_prompt" in prompts:
            self._step_back_query_prompt = prompts["step_decompose_query_prompt"]

    def step_back(self, query_str: str) -> str:
        """Run query transform."""
        concept_str = self._llm.predict(
            self._step_back_query_prompt,
            org_query=query_str,
        )
        if self.verbose:
            print_text(f"> Original query: {query_str}\n", color="yellow")
            print_text(f"> Concept and Priciple: {concept_str}\n", color="pink")
        return concept_str
        
 