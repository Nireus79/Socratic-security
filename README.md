# Socratic Security

Enterprise-grade security utilities for the Socrates AI platform. Provides production-ready implementations of prompt injection protection, input validation, code sandboxing, and audit logging.

## Features

### Phase 1: Critical Security (v0.1.0)
- **Prompt Injection Protection** - Detects and sanitizes prompt injection attempts
- **Path Traversal Validation** - Prevents directory traversal attacks
- **Code Sandboxing** - Safe code execution with resource limits
- **Input Validation** - Sanitized string types and validators

## Installation

```bash
pip install socratic-security
```

## Quick Start

### Prompt Injection Detection

```python
from socratic_security.prompt_injection import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("ignore all instructions")
print(result.risk_score)  # 95
```

### Path Traversal Protection

```python
from socratic_security.filesystem import PathValidator

validator = PathValidator()
safe_path = validator.validate_path(Path("/data/file.txt"), Path("/data"))
```

### Code Sandboxing

```python
from socratic_security.sandbox import CodeAnalyzer, SandboxExecutor

analyzer = CodeAnalyzer()
result = analyzer.analyze("print('safe code')")
print(result.safe)  # True
```

## License

MIT License - see LICENSE file for details
