---
name: Bug Report
about: Report a bug or unexpected behavior
title: ''
labels: bug
assignees: ''
---

**python-icap version**
<!-- Run: pip show python-icap -->

**Environment**
- Python version:
- OS:

**Which client are you using?**
- [ ] `IcapClient` (sync)
- [ ] `AsyncIcapClient` (async)
- [ ] pytest plugin fixtures

**ICAP Server**
- Server type (e.g., c-icap, SquidClamav):
- Server version (if known):

**Description**
A clear description of the bug.

**Minimal Reproducible Example**
```python
# Paste a minimal example that reproduces the issue
from icap import IcapClient

with IcapClient('localhost') as client:
    # ...
```

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened. Include any error messages or tracebacks.

**Debug logs (if applicable)**
```
# Enable debug logging and paste relevant output:
# import logging
# logging.basicConfig(level=logging.DEBUG)
```