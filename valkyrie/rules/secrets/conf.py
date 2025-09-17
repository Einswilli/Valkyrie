import re
from pydantic import Field
from typing import (
    Set, Pattern, List
)

from valkyrie.core import BaseConfigModel
from valkyrie.rules.base import BaseRuleConfig


####
##      SECURITY RULE CONFIG
#####
class SecretsRuleConfig(BaseRuleConfig):
    """Secrets Rule Confiiguration model."""

    patterns: List['SecretPattern']


####
##      SECRET PATTERN MODEL
#####

class SecretPattern(BaseConfigModel):
    """Pattern definition for secret detection"""

    name: str
    pattern: Pattern[str]
    entropy_threshold: float = 0.0
    keywords: Set[str] = Field(default_factory=set)
    file_extensions: Set[str] = Field(default_factory=set)


####    
SECRETS_PATTERNS = [
    SecretPattern(
        name = "AWS Access Key",
        pattern = re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
        keywords = {"aws", "amazon", "access", "key"}
    ),
    SecretPattern(
        name = "Generic API Key",
        pattern = re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-z0-9]{20,})', re.IGNORECASE),
        entropy_threshold = 3.5
    ),
    SecretPattern(
        name = "JWT Token",
        pattern = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
        keywords = {"jwt", "token", "bearer"}
    ),
    SecretPattern(
        name = "GitHub Token",
        pattern = re.compile(r'gh[pousr]_[A-Za-z0-9_]{36}'),
        keywords = {"github", "token"}
    ),
    SecretPattern(
        name = "Private Key",
        pattern = re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'),
        keywords = {"private", "key", "rsa", "ssh"}
    ),
    SecretPattern(
        name = "Database Connection String",
        pattern = re.compile(r'(mongodb|mysql|postgres|redis)://[^\s]+', re.IGNORECASE),
        keywords = {"database", "connection", "string"}
    )
]