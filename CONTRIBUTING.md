# Contributing to synpareia

Thanks for your interest in contributing to synpareia -- a cryptographic trust layer for AI agents. We welcome contributions that improve the library.

## Quick Start

1. Fork the repository and clone your fork
2. Install dependencies: `uv sync --extra dev`
3. Run the test suite to confirm everything works: `make test`

## Development Workflow

1. Create a branch from `main` for your change
2. Make your changes
3. Run quality checks:
   ```bash
   make format     # ruff format
   make lint       # ruff check
   make typecheck  # mypy strict mode
   make test       # full test suite
   ```
4. Push your branch and open a pull request

## Code Style

- **Formatting and linting:** ruff (configured in `pyproject.toml`)
- **Type checking:** mypy with strict mode
- **Imports:** sorted by ruff's isort rules

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding or updating tests
- `refactor:` code change that neither fixes a bug nor adds a feature

## Pull Requests

- All CI checks must pass before merge
- Keep PRs focused on a single change
- New features require tests
- Bug fixes require a regression test
- Update documentation if your change affects the public API
- No secrets or credentials in diffs

## Questions?

Open a [discussion](https://github.com/synpareia/synpareia/discussions) or file an issue. We're happy to help.
