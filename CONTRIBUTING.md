# 🛡️ Valkyrie - Contribution Guide

Thank you for your interest in contributing to Valkyrie! This guide will help you get started with the project.

## 📋 Table of Contents
1. [Getting Started](#getting-started)
2. [Project Structure](#project-structure)
3. [Development Workflow](#development-workflow)
4. [Code Conventions](#code-conventions)
5. [Testing & Quality](#testing--quality)
6. [Documentation](#documentation)
7. [Reporting Bugs](#reporting-bugs)
8. [Feature Proposals](#feature-proposals)
9. [Code of Conduct](#code-of-conduct)

---

## 1. Getting Started <a name="getting-started"></a>

### Prerequisites
- Python 3.10+
- Git
- uv (for dependency management)

### Initial Setup
```bash
# Fork the repository
git clone https://github.com/AllDotPy/Valkyrie.git
cd valkyrie

# Install dependencies
uv sync

# Install pre-commit hooks
uv run pre-commit install

# Verify installation
uv run valkyrie --version
```

### Development Environment
We recommend using VS Code with the following extensions:
- Python
- Pylance
- Ruff
- Pre-commit

---

## 2. Project Structure <a name="project-structure"></a>

```
valkyrie/
├── valkyrie/
│   ├── core/
│   │   ├── scanner.py          # Main Engine 
│   │   ├── types.py            # Common Types
│   │   └── exceptions.py       # Custom Exceptions 
│   ├── plugins/
│   │   ├── __init__.py         # Plugin manager
│   │   ├── secrets.py          # Plugin secrets
│   │   ├── dependencies.py     # Plugin deps
│   │   └── iam.py              # Plugin IAM
│   ├── integrations/
│   │   ├── github.py           # GitHub Actions
│   │   ├── gitlab.py           # GitLab CI
│   │   └── formatters.py       # SARIF, HTML, etc.
│   └── cli.py                  # CLI Interface
├── rules/                      # Local Rules
├── tests/                      # Comprehensive test suite
├── docs/                       # Documentation
├── .github/workflows/          # GitHub Actions
├── valkyrie.yaml              # Configuration
├── pyproject.toml             # Python packaging
└── README.md                  # Documentation utilisateur
```

---

## 3. Development Workflow <a name="development-workflow"></a>

### Branch Strategy
- `master` - Stable production branch
- `develop` - Integration branch for features
- `feature.*` - New features
- `fix.*` - Bug fixes
- `docs.*` - Documentation improvements

### Contribution Process
1. **Find an Issue** - Look for `good first issue` or `help wanted` labels
2. **Discuss** - Comment on the issue to discuss approach
3. **Branch** - Create a feature branch from `develop`
4. **Code** - Implement your changes
5. **Test** - Add tests and ensure they pass
6. **Commit** - Use conventional commit messages
7. **PR** - Open a pull request against `develop`

### Commit Message Convention
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Example**:
```
feat(scanner): add AWS secret detection

- Implement regex pattern for AWS access keys
- Add whitelist for common false positives
- Include comprehensive tests

Closes #123
```

---

## 4. Code Conventions <a name="code-conventions"></a>

### Python Style
- Follow PEP 8 guidelines
- Use type hints extensively
- Maximum line length: 100 characters
- Use Google-style docstrings

**Example**:
```python
def scan_file(file_path: Path, rules: List[Rule]) -> List[Finding]:
    """Scan a single file against provided rules.
    
    Args:
        file_path: Path to the file to scan
        rules: List of rules to apply
        
    Returns:
        List of findings discovered in the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If unable to read the file
    """
    # Implementation
```

### Import Organization
```python
# Standard library
import os
import re
from pathlib import Path
from typing import List, Optional

# Third-party
import requests
from pydantic import BaseModel

# Local imports
from valkyrie.domain.entities import Finding
from valkyrie.domain.rules import Rule
```

---

## 5. Testing & Quality <a name="testing--quality"></a>

### Running Tests
```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=valkyrie

# Run specific test
uv run pytest tests/domain/test_rules.py -v

# Run linting
uv run ruff check .
uv run mypy src/
```

### Test Structure
- **Unit Tests**: `tests/unit/` - Test individual components
- **Integration Tests**: `tests/integration/` - Test component interactions
- **E2E Tests**: `tests/e2e/` - Test complete workflows

### Quality Gates
- ✅ All tests pass
- ✅ 90%+ test coverage
- ✅ No linting errors
- ✅ Type checking passes
- ✅ Documentation updated

---

## 6. Documentation <a name="documentation"></a>

### Documentation Types
1. **Code Documentation** - Docstrings and type hints
2. **User Documentation** - Usage guides and examples
3. **API Documentation** - Auto-generated API references
4. **Rule Documentation** - Rule specifications and examples

### Adding New Rules
Create a markdown file in `docs/rules/` with:

```markdown
# Rule ID: aws.access-key-id

## Description
Detects AWS Access Key IDs in code

## Patterns
- `AKIA[0-9A-Z]{16}`
```

## Examples

### Positive
```python
# This will trigger a finding
aws_key = "AKIAIOSFODNN7EXAMPLE"
```

### Negative
```
# This won't trigger (whitelisted)
aws_key = "AKIAEXAMPLEEXAMPLE"
```

## Severity
High

## Tags
aws, credentials, secrets


---

## 7. Reporting Bugs <a name="reporting-bugs"></a>

### Bug Report Template
```markdown
## Description
Clear and concise description of the bug.

## Steps to Reproduce
1. Run command '...'
2. Scan file '...'
3. See error

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- Valkyrie Version: [e.g., 0.1.0]
- Python Version: [e.g., 3.10.8]
- OS: [e.g., Ubuntu 22.04]

## Additional Context
Logs, screenshots, or any other relevant information.
```

---

## 8. Feature Proposals <a name="feature-proposals"></a>

### Proposal Template
```markdown
## Problem Statement
Describe the problem this feature solves.

## Proposed Solution
Describe your proposed solution.

## Alternatives Considered
Describe alternative solutions you've considered.

## Use Cases
Describe specific use cases this would enable.

## Implementation Notes
Any technical considerations or suggestions.
```

---

## 9. Code of Conduct <a name="code-of-conduct"></a>

### Our Pledge
We are committed to providing a friendly, safe, and welcoming environment for all.

### Our Standards
- ✅ Use welcoming and inclusive language
- ✅ Respect different viewpoints and experiences
- ✅ Accept constructive criticism gracefully
- ✅ Focus on what's best for the community

### Unacceptable Behavior
- ❌ Harassment of any kind
- ❌ Trolling or insulting comments
- ❌ Public or private harassment
- ❌ Publishing others' private information

### Enforcement
Violations may result in temporary or permanent bans from the community.

---

## 🎯 Getting Help

- **Discussions**: GitHub Discussions for questions
- **Issues**: Bug reports and feature requests
- **Discord**: Real-time chat (link in README)
- **Documentation**: Check the docs/ folder first

## 🏆 Your First Contribution

1. Look for issues labeled `good first issue`
2. Comment on the issue to express interest
3. Follow the development workflow
4. Ask for help if needed!

Thank you for helping make Valkyrie better! 🚀