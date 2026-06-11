# Contributing to BugHunterPro

Thank you for your interest in contributing to BugHunterPro!

## How to Report Bugs

If you find a bug:
1. Check if it's already reported in Issues
2. Include:
   - Clear description of the bug
   - Steps to reproduce it
   - Expected vs actual result
   - Your system info (OS, Python version, etc.)

## How to Suggest Enhancements

1. Open an Issue with label 'enhancement'
2. Describe the improvement and its value
3. Wait for feedback before implementing

## How to Submit Code

1. Fork the repository
2. Create a feature branch: git checkout -b feature/MyFeature
3. Make your changes
4. Follow PEP 8 style guide
5. Add docstrings to new functions
6. Commit: git commit -m "Add feature: description"
7. Push: git push origin feature/MyFeature
8. Open a Pull Request

## Code Style

- Follow PEP 8
- Use meaningful variable names
- Add comments for complex logic
- Write docstrings for functions

## Testing

Please add tests for new features:

\\\python
import unittest
from BugHunterPro import BugHunterPro

class TestBugHunterPro(unittest.TestCase):
    def test_subdomain_enumeration(self):
        hunter = BugHunterPro("example.com")
        result = hunter.hunt()
        self.assertIsNotNone(result)
\\\

## License

By contributing, you agree your code will be licensed under the MIT License.
