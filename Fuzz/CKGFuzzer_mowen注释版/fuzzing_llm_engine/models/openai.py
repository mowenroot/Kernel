from models.baseLLM import BaseLLM
from openai import OpenAI
from configs.llm_config import LLMConfig
from openai.types.chat import ChatCompletion

class OpenAIModel(BaseLLM):
    def __init__(self, model_name, llm_config: LLMConfig):
        self.model_name = model_name
        self.llm_config = llm_config
        self.client = OpenAI(api_key=self.llm_config.api_key)


    def generate(self, messages, **kwargs):
        '''
        messages=[
        {"role": "system", "content": "You are a helpful assistant"},
        {"role": "user", "content": "Hello"},
        ]
        '''
        llm_config = self.llm_config.model_dump()
        for key, default_value in llm_config.items():
            if key not in kwargs:
                kwargs[key] = default_value
                    
        response: ChatCompletion = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            **kwargs
        )
        self._update_costs(response.usage)
        return response

    def get_model_info(self):
        return {
            "name": "OpenAI",
            "Model": self.model_name,
            "Default Config": self.llm_config.model_dump()
        }