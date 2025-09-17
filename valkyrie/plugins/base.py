"""
Valkyrie - Plugin module.
"""
from abc import abstractmethod
from pathlib import Path
from typing import (
    List, Dict, Any, Optional,
    ClassVar, Type, Union, TypeVar
)

from valkyrie.utils import (
    import_module_from,
)
from ..core.types import (
    ScanRule,
    Plugin
)
from ..core.conf import PluginConfig


#### PLUGINS GENERIC TYPE
T = TypeVar('T', bound = 'PluginConfig')

#### PLUGINS DIR
PLUGINS_DIR = 'valkyrie.plugins.{}'


####
##      SCANNER PLUGIN
####
class ScannerPlugin(Plugin):
    """Base class for all Valkyrie Scanner Plugins."""

    config_class: Type[PluginConfig] = PluginConfig
    """Plugin configuration model class."""

    rule_config_class: Type[]

    category: 

    def __init__(
        self,
        config: Optional[PluginConfig] = None
    ):
        """Initialize plugin."""

        self.config = config

    @classmethod
    def with_config(cls, config: Dict[str, Any]):
        """Iniitiallize plugin with given config."""

        return cls(cls.config_class.from_json(config))
    
    @abstractmethod
    async def get_rules(self) -> List[ScanRule]:
        """Return list of rules provided by this plugin"""
        pass


####
##      PLUGINS REGISTRY CLASS
#####
class PluginsRegistry:
    """
    Registry for all valkyrie plugins.
    This class is used to register and retrieve plugins based on their names.
    """
    
    _registry: ClassVar[Dict[str, Type[ScannerPlugin]]] = {} # type: ignore

    @classmethod
    def register(cls, name: Optional[str] = None) -> None: # type: ignore
        """Register a new plugin class."""

        def wrapper(plugin: Type[ScannerPlugin]):
            """Wrapper"""

            nonlocal name
            name = name or plugin.name()
            if name not in cls._registry.keys():
                cls._registry[name] = plugin
                
            return plugin

        return wrapper

    @classmethod
    def get(cls, name: str) -> Type[ScannerPlugin]: # type: ignore
        """Get a registered Plugin class by its name."""

        if name not in cls._registry:
            raise ValueError(
                f"Invalid Adapter name: '{name}' not found."
                )
        
        return cls._registry[name]

    @classmethod
    def all(cls) -> List[Type[ScannerPlugin]]: # type: ignore
        """Get all registered Plugin classes."""
        return list(cls._registry.values())

    @classmethod
    def clear(cls) -> None:
        """Clear the registry."""
        cls._registry.clear()

    @classmethod
    def list(cls) -> List[str]:
        """List all registered Plugins names."""
        return list(cls._registry.keys())


####    UTILITIES
def register_plugin(name: Optional[str] = None):
    """
    A Shirtcut to register valkyrie plugins.

    Usage:
    ```python
    @register_plugin()
    class Mylugin(ScannerPlugin):
        ...

        @property
        def name(self):
            return 'my-plugin'
    ```
    """

    return PluginsRegistry.register(name = name)

####    IMPORRT PLUGIN
def import_plugin(name: Union[str,Path]):
    """Load plugin from plugin dir"""

    return import_module_from(
        PLUGINS_DIR.format(name)
    )