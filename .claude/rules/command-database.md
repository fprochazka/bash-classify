---
paths:
  - "src/bash_classify/commands/**"
---

@docs/classification-guidance.md
@schemas/command.schema.json

Every YAML file must:
- Start with `# $schema: ../../../schemas/command.schema.json` on the first line
- Have a `command:` field matching the filename (without `.yaml`)
- Have a `description:` field with a short one-liner
- Pass schema validation (`uv run pytest tests/test_schema.py`)
