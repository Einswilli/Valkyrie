import logging
from typing import Union, Any
from types import ModuleType
from pathlib import Path
from importlib import import_module

import yaml

from .context import ValkyrieContext

__all__ = [
    ValkyrieContext,
    'import_module_from'
]


# VALLKYRIE LOGGER UTILITY
def get_logger(name: str) -> logging.Logger:
    """Gets a logger from the global context"""

    base_logger = ValkyrieContext.get_data("logger")
    if base_logger is None:

        # Fallback if the context is not initialized
        logger = logging.getLogger(name)
        logger.addHandler(logging.NullHandler())
        return logger
    return base_logger.getChild(name)

# GET CONTEXT
def get_context() -> ValkyrieContext:
    """Return Valkyrie global context"""

    return ValkyrieContext

# LOAD YAML FILE
def load_yaml(file: Union[str, Path]) -> Any:
    """Load ad return a .yaml file content"""

    path = Path(file)
    return yaml.safe_load(path.read_text(encoding='utf-8'))

# IMPORT MODULE
def import_module_from(path: Union[str,Path]) ->'ModuleType':
    """Import module using importlib"""
    
    return import_module(path)