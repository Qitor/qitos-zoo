# App Template

Recommended app shape:

```text
apps/<app-name>/
  README.md
  src/
  configs/
  prompts/
  examples/
  tests/
```

Keep reusable app-local helpers in `shared/qitos_zoo_common` only when multiple apps need them. Promote code into QitOS core only after it is generic, tested, documented, and used by multiple independent apps.
