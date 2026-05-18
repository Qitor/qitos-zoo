# Adding A New Agent

Add new product-grade agents under `apps/`.

Before adding an app, check:

- It is an application, not a generic QitOS framework primitive.
- It does not require QitOS core to import from qitos-zoo.
- Security-sensitive behavior is documented and opt-in.
- Dependencies are app-local or clearly documented.
- Tests avoid external services unless they are explicitly marked.
