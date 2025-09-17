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
