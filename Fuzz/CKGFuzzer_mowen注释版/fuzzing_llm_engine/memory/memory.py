

from llama_index.core.memory import (
    VectorMemory,
    SimpleComposableMemory,
    ChatMemoryBuffer,
)
from llama_index.core.llms import ChatMessage
from typing import List

class MemoryManager:
    composable_memory = {}
    def add_memory(self, memory_name, llm_embedding):
        chat_memory_buffer = ChatMemoryBuffer.from_defaults()
        vector_memory = VectorMemory.from_defaults(
            vector_store=None,  # leave as None to use default in-memory vector store
            embed_model=llm_embedding,
            retriever_kwargs={"similarity_top_k": 1},
        )
        self.composable_memory[memory_name] = SimpleComposableMemory.from_defaults(
            primary_memory=chat_memory_buffer,
            secondary_memory_sources=[vector_memory],
        )
    
    def get_memory(self, memory_name):
        return self.composable_memory[memory_name] if memory_name in self.composable_memory else None
    
    def put_message(self, msg:ChatMessage, memory_name:str):
        if memory_name in self.composable_memory:
            self.composable_memory[memory_name].put(msg)
            return True
        return False
    
    def set_messages(self, msgs: List[ChatMessage], memory_name:str):
        if memory_name in self.composable_memory:
            self.composable_memory[memory_name].set(msgs)
            return True
        return False
    
    def get_messages(self, memory_name)