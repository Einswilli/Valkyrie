"""
Valkyrie - Plugin Manager.
"""
from typing import (
    List, Set, Dict, Any, Optional,
)
import logging

from valkyrie.utils import (
    get_logger,
    get_context
)
from valkyrie.core.types import (
    ScanRule,
)

from .base import (
    ScannerPlugin, import_plugin,
    PluginsRegistry
)


####
##      PLUGUN MANAGER CLASS
#####
class PluginManager:
    """Manages scanner plugins and their lifecycle"""
    
    def __init__(
        self,
        logger: Optional[logging.Logger] = None
    ):
        self.plugins: Dict[str, ScannerPlugin] = {}
        self.enabled_plugins: Set[str] = set()
        self.logger = logger or get_logger('Valkyrie.PluginManager')


    @classmethod
    async def load_from_config(cls, config: Dict[str,Any]):
        """Detect and load plugins from config"""

        ctx = get_context()
        cmd_args = ctx.get_data('cmd_arrgs')

        plugins = config
        for plugin_name in plugins.keys():

            try:
                import_plugin(plugin_name)
                # Log if verbose
                if cmd_args.verbose:
                    cls.logger.info(
                        f'{plugin_name} plugin loaded...'
                    )
                    
            # Error importing plugin
            except Exception as e:
                if cmd_args.verbose:
                    cls.logger.warning(
                        f'Error loading {plugin_name} {e}'
                    )

        # Use Regiistry to initialize plugins
        for plugin in PluginsRegistry.all():
            await cls.register_plugin(
                plugin.with_config(config.get(plugin.name))
            )
    
    async def register_plugin(
        self, 
        plugin: ScannerPlugin, 
        config: Dict[str, Any] = None
    ) -> None:
        """Register and initialize a plugin"""
        
        await plugin.initialize(config or {})
        self.plugins[plugin.name] = plugin
        self.enabled_plugins.add(plugin.name)
    
    async def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a plugin"""

        if plugin_name in self.plugins:
            await self.plugins[plugin_name].cleanup()
            del self.plugins[plugin_name]
            self.enabled_plugins.discard(plugin_name)
    
    def enable_plugin(self, plugin_name: str) -> None:
        """Enable a registered plugin"""

        if plugin_name in self.plugins:
            self.enabled_plugins.add(plugin_name)
    
    def disable_plugin(self, plugin_name: str) -> None:
        """Disable a plugin"""
        self.enabled_plugins.discard(plugin_name)
    
    async def get_all_rules(self) -> List[ScanRule]:
        """Get rules from all enabled plugins"""
        
        all_rules = []
        
        for plugin_name in self.enabled_plugins:
            if plugin_name in self.plugins:
                plugin_rules = await self.plugins[plugin_name].get_rules()
                all_rules.extend(plugin_rules)
        
        return all_rules
    
    async def cleanup_all(self) -> None:
        """Cleanup all plugins"""
        for plugin in self.plugins.values():
            await plugin.cleanup()
        
        self.plugins.clear()
        self.enabled_plugins.clear()
