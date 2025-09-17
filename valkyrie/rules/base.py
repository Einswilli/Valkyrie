"""
Valkyrie - Rules module.
"""
import logging
from pathlib import Path
from abc import abstractmethod
from typing import (
    List, Optional, Dict, Any, ClassVar, 
    Type, Set, Union, TypeVar
)

from pydantic import Field

from valkyrie.core import (
    RuleMetadata, SecurityFinding, ScanRule,
    BaseConfigModel, FindingCategory, SeverityLevel
)
from valkyrie.utils import (
    get_logger,
)

T = TypeVar('T', bound = 'BaseSecurityRule')
V = TypeVar('V', bound = 'BaseRuleConfig')

####
##      SECURITY RULE CONFIG
#####
class BaseRuleConfig(BaseConfigModel):
    """Base class for all Secutiry rules configuration models."""

    id: str
    """Rulle identifyer"""

    name: str
    """Rulee name"""

    description: Optional[str] = None
    """Rulle Description (Optional)"""

    category: FindingCategory
    """Rule Category"""

    severity: SeverityLevel = SeverityLevel.LOW
    """Rule severity level"""

    author: Optional[str] = 'Valkyrie Community'
    """Rule author"""

    version: Optional[str] = '1.0.0'
    """Rule version"""

    tags: Set[str] = Field(
        default_factory = lambda: set
    )
    """Rule tags"""

    enabled: bool = True
    """Is rule enabled / disabe"""

    file_extensions: Set[str] = Field(
        default_factory = lambda: set
    )
    """supported File extensions for the rule"""

    exclude_patterns: Set[str] = Field(
        default_factory = lambda: set
    )
    """Files to exclude"""

    remediation: Optional[str] = None
    """Remediiation message"""

    references: Optional[List[str]] = None
    """References"""


####
##      BASE CLASS FOR SECURITY RULE IMPLEMENTATION
#####
class BaseSecurityRule(ScanRule):
    """Base implementation for security rules"""

    name: ClassVar[str]
    description: str =  'Valkyrie Detection Rule'
    
    def __init__(
        self, 
        config: V,
        logger: Optional[logging.Logger] = None
    ):
        self.config: V = config
        self._metadata = self.build_metadada()

        # Configure logger
        self.logger = logger or get_logger(
            f'Valkyrie.{self.__class__.__name__}'
        )
    
    @property
    def metadata(self) -> RuleMetadata:
        return self._metadata
    
    @classmethod
    def from_config(
        cls, 
        config: BaseRuleConfig
    ) -> 'T':
        """Load and return a SecretsDetection Rule instance from config"""

        ...
    
    @classmethod
    def from_yaml(
        cls, 
        file: Union[str, Path]
    )-> 'T':
        """Load Rule fom .yaml file"""

        ...

    @classmethod
    def from_json(
        cls, 
        json_content: Dict[str, Any]
    )-> 'T':
        """Load Rule fom json content (python dict)"""
        
        ...

    def build_metadada(self,config: V) -> RuleMetadata:
        """Build rule metadata from config"""

        return RuleMetadata(
            id = config.id or f"secrets-{id(self)}",
            name = config.name or "Generic Secrets Detection",
            description = (
                config.description 
                or self.description
            ),
            category = FindingCategory(config.category),
            severity = SeverityLevel(self.config.severity),
            author = config.author or "Valkyrie Core Team",
            tags = set(config.tags)
        )

    def to_json(self) -> Dict[str, Any]:
        """Return rule as Json object"""

        return self.config.to_json()

    def is_applicable(self, file_path: Path) -> bool:
        """Default implementation - override in subclasses"""
        return True
    
    async def scan(
        self, 
        file_path: Path, 
        content: str
    ) -> List[SecurityFinding]:
        """Override in subclasses"""
        
        return []
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with configuration"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass


####
##      RULES REGISTRY CLASS
#####
class RulesRegistry:
    """
    Registry for all valkyrie Rules.
    This class is used to register and retrieve Rules based on their categories.
    """
    
    _registry: ClassVar[Dict[str, Type[BaseSecurityRule]]] = {} # type: ignore

    @classmethod
    def register(cls) -> None: # type: ignore
        """Register a new rule class."""

        def wrapper(rule_class: Type[BaseSecurityRule]):
            """Wrapper"""

            name = rule_class.metadata.category
            if name not in cls._registry.keys():
                cls._registry[name] = rule_class
                
            return rule_class

        return wrapper

    @classmethod
    def get(cls, name: str) -> Type[BaseSecurityRule]: # type: ignore
        """Get a registered Rule class by its name."""

        if name not in cls._registry:
            raise ValueError(
                f"Invalid Adapter name: '{name}' not found."
                )
        
        return cls._registry[name]

    @classmethod
    def all(cls) -> List[Type[BaseSecurityRule]]: # type: ignore
        """Get all registered Rule classes."""
        return list(cls._registry.values())

    @classmethod
    def clear(cls) -> None:
        """Clear the registry."""
        cls._registry.clear()

    @classmethod
    def list(cls) -> List[str]:
        """List all registered rules names."""
        return list(cls._registry.keys())


####    UTILITIES
def register_rule():
    """
    A Shirtcut to register valkyrie plugins.

    Usage:
    ```python
    @register_rule()
    class MylRule(BaseSecurityRule):
        ...

        @property
        def name(self):
            return 'my-plugin'
    ```
    """

    return RulesRegistry.register()
