#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Time    : 2024/1/4 16:33
@Author  : alexanderwu
@File    : llm_config.py
"""
from enum import Enum
from typing import Optional

from pydantic import field_validator
from utils.yaml_model import YamlModel


class LLMType(Enum):
    OPENAI = "openai"
    DeepSeek = "deepseek"
    OPEN_LLM = "open_llm"
    def __missing__(self, key):
        return self.OPENAI


class LLMConfig(YamlModel):
    """Config for LLM

    OpenAI: https://github.com/openai/openai-python/blob/main/src/openai/resources/chat/completions.py#L681
    Optional Fields in pydantic: https://docs.pydantic.dev/latest/migration/#required-optional-and-nullable-fields
    """

    api_key: str = "sk-"
    api_type: LLMType = LLMType.OPENAI
    base_url: str = "https://api.openai.com/v1"
    api_version: Optional[str] = None

    model: Optional[str] = None  # also stands for DEPLOYMENT_NAME
    pricing_plan: Optional[str] = None  # Cost Settlement Plan Parameters.

    # For Chat Completion
    max_token: int = None
    temperature: float = None
    top_p: float = None
    top_k: int = None
    repetition_penalty: float = None
    stop: Optional[str] = None
    presence_penalty: float = None
    frequency_penalty: float = None
    best_of: Optional[int] = None
    n: Optional[int] = None
    stream: bool = True
    # https://cookbook.openai.com/examples/using_logprobs
    logprobs: Optional[bool] = None
    top_logprobs: Optional[int] = None
    timeout: int = 600


    # For Network
    proxy: Optional[str] = None

    # Cost Control
    calc_usage: bool = True

    @field_validator("api_key")
    @classmethod
    def check_llm_key(cls, v):
        if v in ["", None, "YOUR_API_KEY"]:
            raise ValueError("Please set your API key in config2.yaml")
        return v