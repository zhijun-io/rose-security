# Repository task prompt

Use this prompt when assigning a focused follow-up task in this repository:

```text
Work in the existing Rose Security repository. Before editing, inspect AGENTS.md, the Maven modules, relevant source/tests/docs, and git status. Preserve unrelated worktree changes.

Use the versions and APIs declared by the repository; currently Java 25, Spring Boot 4.1.2, and Spring Security 7. Keep the host application in control of its SecurityFilterChain, authorization, CSRF/CORS, user model, and API error format.

Prefer Spring Security's native extension points and existing module boundaries. Keep MFA optional and outside the base starter. Do not add OAuth/OIDC, authorization-server behavior, rate limiting, business user/role models, or new abstractions unless the task explicitly asks for them. Do not describe planned features as implemented.

Make the smallest behavior-preserving change that meets the task. Add targeted tests for changed behavior, including relevant failure paths. Run the appropriate Maven Wrapper checks and report exactly which compilation, formatting, tests, and verification commands passed or failed. Do not claim unrun checks passed.
```
