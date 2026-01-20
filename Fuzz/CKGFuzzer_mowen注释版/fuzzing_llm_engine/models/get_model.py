from llama_index.llms.openai_like import OpenAILike
from llama_index.llms.ollama import Ollama
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
import os



def get_model(llm_config=None):
    # 默认使用 llama3:70b
    if llm_config is None:
        return Ollama(model="llama3:70b",  base_url="http://csl-server14.dynip.ntu.edu.sg:51030", request_timeout=3600) # http://csl-server14.dynip.ntu.edu.sg:51030"
    # 三个类型的模型可选
    model_name = llm_config['model']
    if model_name.startswith("deepseek"):
        return OpenAILike(model=model_name, api_base=llm_config["base_url"], api_key=llm_config["api_key"], is_chat_model=True, temperature=llm_config["temperature"] )
    if model_name.startswith("openai"):
        model_name = model_name.replace("openai-", "").strip()
        return OpenAILike(model=model_name, api_base=llm_config["base_url"], api_key=llm_config["api_key"], is_chat_model=True, temperature=llm_config["temperature"])
    if model_name.startswith("ollama"):
        model_name = model_name.replace("ollama-", "").strip()
        return Ollama(model=model_name,  base_url=llm_config["base_url"], request_timeout=llm_config["request_timeout"]) # http://csl-server14.dynip.ntu.edu.sg:51030"
    assert False, f"Non-support Model Name, The LLM config is {llm_config}. Please use the Ollama Model, OpenAI model and Deepseek Model"
# Patch
def get_embedding_model(llm_config=None, device='cpu'):
    if llm_config is None:
        # 本地部署的模型
        return HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5",device=device)
        #return OllamaEmbedding( model_name = "llama3:70b", base_url="http://csl-server14.dynip.ntu.edu.sg:51030", ollama_additional_kwargs={"mirostat": 0})
    model_name = llm_config['model']
    if model_name.startswith("openai"):
        return OpenAIEmbedding(model=model_name, api_key=llm_config.api_key)
    if model_name.startswith("ollama"):
        model_name = model_name.replace("ollama-", "").strip()
        return OllamaEmbedding( model_name = model_name, base_url=llm_config["base_url"], ollama_additional_kwargs={"mirostat": 0})
    assert False, f"Non-support Emb Model Name, The LLM config is {llm_config}. Please use the Ollama Model, OpenAI model and Deepseek Model"

