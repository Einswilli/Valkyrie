import yaml
from pathlib import Path
from typing import Dict, List, Optional

from valkyrie.core import (
    RuleRepository
)
from valkyrie.rules.base import RulesRegistry, BaseSecurityRule


####
##      LOCAL RULE REPOSITORY
#####
class LocalRuleRepository(RuleRepository):
    """Rule repository backed by local files"""
    
    def __init__(self, rules_directory: Path):
        self.rules_directory = rules_directory
        self.rules_cache: Dict[str, BaseSecurityRule] = {}
    
    async def load_rules(self) -> List[BaseSecurityRule]:
        """Load rules from local directory"""
        
        rules = []
        
        if not self.rules_directory.exists():
            return rules
        
        for rule_file in self.rules_directory.glob("*.yaml"):
            try:
                content = rule_file.read_text(encoding='utf-8')
                rule_data = yaml.safe_load(content)
                
                # Create rule based on rule category
                rule_class = RulesRegistry.get(rule_data.get('category'))
                rule = rule_class.from_json(rule_data)
                
                rules.append(rule)
                self.rules_cache[rule.metadata.id] = rule
                
            except Exception as e:
                # Log error but continue loading other rules
                continue
        
        return rules
    
    async def get_rule(
        self, 
        rule_id: str
    ) -> Optional[BaseSecurityRule]:
        """Get specific rule by ID"""

        if not self.rules_cache:
            await self.load_rules()
        return self.rules_cache.get(rule_id)
    
    async def add_rule(self, rule: BaseSecurityRule) -> None:
        """Add new rule to local repository"""

        rule_file = self.rules_directory / f"{rule.metadata.id}.yaml"
        
        # Convert rule into JSON format
        rule_data = rule.to_json()
        
        with open(rule_file, 'w', encoding='utf-8') as f:
            yaml.dump(rule_data, f, default_flow_style=False)
        
        self.rules_cache[rule.metadata.id] = rule
    
    async def update_rule(self, rule: BaseSecurityRule) -> None:
        """Update existing rule"""
        await self.add_rule(rule)
        