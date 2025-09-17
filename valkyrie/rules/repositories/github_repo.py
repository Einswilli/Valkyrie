import os
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml
import aiohttp

from valkyrie.core import (
    RuleRepository, SecurityFinding,
    RuleMetadata, FileLocation, RuleRepositoryConfig
)
from valkyrie.rules.base import RulesRegistry, BaseSecurityRule


####
##      GITHUB RULE REPOSITORY
#####
class GitHubRuleRepository(RuleRepository):
    """Rule repository backed by GitHub"""
    
    def __init__(
        self,
        config: RuleRepositoryConfig
    ):
        self.repository = config.url
        self.branch = config.branch
        self.token = os.getenv(config.token_env)
        self.rules_cache: Dict[str, BaseSecurityRule] = {}
        self.base_url = f"https://api.github.com/repos/{self.repository}"
    
    async def load_rules(self) -> List[BaseSecurityRule]:
        """Load rules from GitHub repository"""

        async with aiohttp.ClientSession() as session:
            headers = {}
            if self.token:
                headers["Authorization"] = f"token {self.token}"
            
            # Get repository contents
            url = f"{self.base_url}/contents/rules?ref={self.branch}"
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    contents = await response.json()
                    rules = []
                    
                    for item in contents:
                        if item["type"] == "file" and item["name"].endswith(".yaml"):
                            rule = await self._load_rule_from_github(session, item["download_url"], headers)
                            if rule:
                                rules.append(rule)
                    
                    return rules
        
        return []
    
    async def _load_rule_from_github(
        self, 
        session: aiohttp.ClientSession, 
        download_url: str, 
        headers: Dict[str, str]
    ) -> Optional[BaseSecurityRule]:
        """Load individual rule from GitHub"""

        try:
            async with session.get(download_url, headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    rule_data = yaml.safe_load(content)
                    return self._create_rule_from_yaml(rule_data)
        except Exception as e:
            # Log error but continue loading other rules
            pass
        
        return None
    
    def _create_rule_from_yaml(
        self, 
        rule_data: Dict[str, Any]
    ) -> Optional[BaseSecurityRule]:
        """Create rule instance from YAML data"""

        try:
            # Create rule based on rule category
            rule_class = RulesRegistry.get(rule_data.get('category'))
            rule = rule_class.from_json(rule_data)
            
            return rule
                
        except Exception as e:
            return None

    
    def _create_generic_rule(
        self, 
        metadata: RuleMetadata, 
        rule_data: Dict[str, Any]
    ) -> BaseSecurityRule:
        """Create generic rule from YAML"""

        class GenericRule(BaseSecurityRule):
            """Generic Rule class"""

            def __init__(
                self, metadata: RuleMetadata, patterns: List[Dict[str, Any]]):
                super().__init__(metadata)
                self.patterns = [re.compile(p["regex"], re.IGNORECASE) for p in patterns]
            
            def is_applicable(self, file_path: Path) -> bool:
                extensions = rule_data.get("file_extensions", [])
                if extensions:
                    return file_path.suffix.lower() in extensions
                return True
            
            async def scan(self, file_path: Path, content: str) -> List[SecurityFinding]:
                findings = []
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern in self.patterns:
                        matches = pattern.finditer(line)
                        for match in matches:
                            finding = SecurityFinding(
                                id = hashlib.md5(f"{file_path}:{line_num}:{self.metadata.id}".encode()).hexdigest(),
                                title = self.metadata.name,
                                description = self.metadata.description,
                                severity = self.metadata.severity,
                                category = self.metadata.category,
                                location = FileLocation(
                                    file_path = file_path,
                                    line_number = line_num,
                                    column_start = match.start(),
                                    column_end = match.end()
                                ),
                                rule_id = self.metadata.id,
                                confidence = 0.7,
                                metadata = {"line_content": line.strip()}
                            )
                            findings.append(finding)
                
                return findings
        
        patterns = rule_data.get("patterns", [])
        return GenericRule(metadata, patterns)
    
    async def get_rule(self, rule_id: str) -> Optional[BaseSecurityRule]:
        """Get specific rule by ID"""

        if rule_id not in self.rules_cache:
            rules = await self.load_rules()
            for rule in rules:
                self.rules_cache[rule.metadata.id] = rule
        
        return self.rules_cache.get(rule_id)
    
    async def add_rule(self, rule: BaseSecurityRule) -> None:
        """Add new rule (would require GitHub API write access)"""

        # Implementation would create PR with new rule
        raise NotImplementedError(
            "Adding rules requires GitHub write access"
            )
    
    async def update_rule(self, rule: BaseSecurityRule) -> None:
        """Update existing rule (would require GitHub API write access)"""

        # Implementation would create PR with rule update
        raise NotImplementedError(
            "Updating rules requires GitHub write access"
        )
