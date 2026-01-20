# Retrievers
from llama_index.core.retrievers import (
    BaseRetriever,
    PGRetriever
)

from typing import List

# import QueryBundle
from llama_index.core import QueryBundle

# import NodeWithScore
from llama_index.core.schema import NodeWithScore


class CodeGraphRetriever(BaseRetriever):
    """Custom retriever that performs both semantic search and hybrid search."""

    def __init__(
        self,
        pg_index_all_code_retriever: PGRetriever,
        pg_index_api_summary_retriever: PGRetriever,
        pg_index_api_code_retriever: PGRetriever,
        pg_index_file_summary_retriever: PGRetriever,
        mode: str = "ALL_CODE",
    ) -> None:
        """Init params."""

        self.pg_index_all_code_retriever = pg_index_all_code_retriever
        self.pg_index_api_summary_retriever = pg_index_api_summary_retriever
        self.pg_index_api_code_retriever = pg_index_api_code_retriever
        self.pg_index_file_summary_retriever = pg_index_file_summary_retriever
        # if mode not in ("ALL_CODE", "API_CODE", "API_SUMMARY", "HYBRID"):
        #     raise ValueError("Invalid mode.")
        self.mode = mode
        super().__init__()

    def _retrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        """Retrieve nodes given query."""
        graph_nodes = []  # Initialize graph_nodes as an empty list

        if self.mode == "ALL_CODE":
            graph_nodes = self.pg_index_all_code_retriever.retrieve(query_bundle)
        elif self.mode == "API_CODE":
            graph_nodes = self.pg_index_api_code_retriever.retrieve(query_bundle)
        elif self.mode == "API_SUMMARY":
            graph_nodes = self.pg_index_api_summary_retriever.retrieve(query_bundle)
        elif self.mode == "FILE_SUMMARY":
            graph_nodes = self.pg_index_file_summary_retriever.retrieve(query_bundle)
        elif self.mode == "HYBRID":
            for retriever in [self.pg_index_all_code_retriever, self.pg_index_api_summary_retriever, 
                            self.pg_index_api_code_retriever, self.pg_index_file_summary_retriever]:
                graph_nodes.extend(retriever.retrieve(query_bundle))
        else:
            raise ValueError(f"Invalid mode: {self.mode}")

        # Remove duplicates
        nodes_dict = {n.node.node_id: n for n in graph_nodes}
        retrieve_nodes = [nodes_dict[rid] for rid in nodes_dict]
        return retrieve_nodes
    
    def set_mode(self, mode: str):
        """Reset mode."""
        self.mode = mode
    
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core import Settings

def get_query_engine(cgretriever, mode: str, llm, synthesizer):
    """
        获取查询引擎

        cgretriever:代码图谱检索器(CodeGraphRetriever),用于根据查询从知识库中提取相关上下文。
        mode:检索模式,比如"HYBRID"（混合）、"KEYWORD"（关键词）、"VECTOR"（向量）等
        llm:大语言模型。
        synthesizer:响应合成器(ResponseSynthesizer),用于将检索器返回的多个片段组合成一个完整的回答。
    """
    cgretriever.set_mode(mode)
    return RetrieverQueryEngine.from_args(
                llm= llm if llm else Settings.llm,
                retriever= cgretriever,
                response_synthesizer=synthesizer,
                verbose=True
            )
    
