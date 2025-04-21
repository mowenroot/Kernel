from llama_index.llms.openai_like import OpenAILike
from models.baseLLM import BaseLLM
from configs.llm_config import LLMConfig
from llama_index.core.llms import ChatMessage, ChatResponse

class LLamaIndexOpenAIModel(BaseLLM):
    def __init__(self, model_name, llm_config: LLMConfig):
        self.model_name = model_name
        self.llm_config = llm_config
        print(llm_config)
        self.client = OpenAILike(model=model_name, api_base=self.llm_config.base_url, api_key=self.llm_config.api_key, is_chat_model=True, temperature=self.llm_config.temperature )


    def generate(self, messages, **kwargs):
        response = self.client.complete(
            messages,
            **kwargs
        )
        # self.cost_manager.update_costs(response.additional_kwargs["usage"])
        return response
    
    def get_model_info(self):
        return {
            "name": "OpenAI",
            "Model": self.model_name,
            "Default Config": self.llm_config.model_dump()
        }