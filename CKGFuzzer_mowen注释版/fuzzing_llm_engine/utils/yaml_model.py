#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Time    : 2024/1/4 10:18
@Author  : alexanderwu
@File    : YamlModel.py
"""
from pathlib import Path
from typing import Dict, Optional, Union

import yaml
from pydantic import BaseModel, model_validator
import os
  
class YamlModel(BaseModel):
    """Base class for yaml model"""

    extra_fields: Optional[Dict[str, str]] = None

    @classmethod
    def read_yaml(cls, file_path: Union[Path, str], encoding: str = "utf-8") -> Dict:
        """Read yaml file and return a dict"""
        # Convert file_path to Path object if it's a str
        file_path = Path(file_path) if isinstance(file_path, str) else file_path
        if not file_path.exists():
            return {}
        with open(file_path, "r", encoding=encoding) as file:
            return yaml.safe_load(file)

    @classmethod
    def from_yaml_file(cls, file_path:  Union[Path, str]) -> "YamlModel":
        """Read yaml file and return a YamlModel instance"""
        # Convert file_path to Path object if it's a str
        file_path = Path(file_path) if isinstance(file_path, str) else file_path
        assert os.path.isfile(file_path), f"{file_path} is not a file"
        return cls(**cls.read_yaml(file_path))

    def to_yaml_file(self, file_path:  Union[Path, str], encoding: str = "utf-8") -> None:
        """Dump YamlModel instance to yaml file"""
        # Convert file_path to Path object if it's a str
        file_path = Path(file_path) if isinstance(file_path, str) else file_path
        with open(file_path, "w", encoding=encoding) as file:
            yaml.dump(self.model_dump(), file)


class YamlModelWithoutDefault(YamlModel):
    """YamlModel without default values"""

    @model_validator(mode="before")
    @classmethod
    def check_not_default_config(cls, values):
        """Check if there is any default config in config2.yaml"""
        if any(["YOUR" in v for v in values]):
            raise ValueError("Please set your config in config2.yaml")
        return values
