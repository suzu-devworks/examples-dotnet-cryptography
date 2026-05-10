# Validation and Commit

## Validation Checklist

- Run `dotnet build` and ensure zero warnings.
- Run `dotnet test` and ensure tests pass (or clearly document skipped tests and why).
- For documentation changes related to Copilot or workspace settings, run `markdownlint` and keep formatting clean.
- If verification is skipped, state the reason and any known risks.
- In PR descriptions, include what changed, why, how it was verified, and remaining risks.

## Commit Convention

Follow Conventional Commits:

```text
type(scope): subject
```

Common types:

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `style`: formatting, no logic change
- `refactor`: neither bug fix nor new feature
- `test`: adding or updating tests
- `chore`: maintenance tasks

Rules:

- Include a brief description in the subject line.
- Add a body for significant changes explaining rationale and verification steps.
- For breaking changes, include `BREAKING CHANGE:` in the body with impact and migration steps.
