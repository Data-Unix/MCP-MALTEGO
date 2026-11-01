## Summary

## How it was verified
- [ ] `uv run pytest -q && uv run ruff check . && uv run mypy src`
- [ ] `npm test` (if the npm launcher changed)
- [ ] `tests/test_schema_portability.py` still passes (Gemini-compatible schemas, ≤ 20 tools)

## Notes for reviewers
