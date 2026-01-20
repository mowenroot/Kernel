import abc
from configs.log import setup_logger

logger = setup_logger()
class BaseLLM(abc.ABC):
    @abc.abstractmethod
    def generate(self, prompt, max_tokens=100, temperature=0.7, top_p=0.9, **kwargs):
        pass
    
    @abc.abstractmethod
    def get_model_info(self):
        pass
