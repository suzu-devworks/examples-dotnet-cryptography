# Tests and Test Assets

## Test Style and Naming

- Test code is written in unit test form, but the primary goal is to demonstrate learning patterns and behavioral verification.
- Prefer BDD-style naming such as `When_..._Then_...` over strict AAA-form names.
- Method names should be descriptive and clearly communicate the scenario.
- Prefer fixture-based setup for reusable key material and use `TestContext.Current.CancellationToken` when asynchronous IO is involved.

Examples:

- `When_SigningAndVerifying_Then_Success`
- `When_ExportedAndImported_Then_PrivateKeyIsRestored`

## Test Assets and Sensitive Files

- Do NOT commit certificates, private keys, or other sensitive test artifacts to the repository.
- Provide idempotent generation scripts under the `scripts/` directory to create required test assets (for example `scripts/openssl-generate.sh`).
- Tests and sample code should read physical files from the path specified by the environment variable `TEST_ASSETS_PATH` rather than relying on tracked binaries.
- Devcontainer and CI should set `TEST_ASSETS_PATH` to a workspace-local assets folder (for example `/workspaces/${localWorkspaceFolderBasename}/assets` or `${{ github.workspace }}/assets`).

## Cryptography-Dependent Tests and Environment Assumptions

- Some tests are intended to run only when required assets, algorithms, providers, or OpenSSL-generated fixtures are available.
- Unless explicitly requested, do not remove or rewrite existing environment-dependent skip logic.
- Follow repository patterns for fixture and environment checks used in cryptography tests.
- When a test verifies interoperability (for example OpenSSL/BouncyCastle/.NET), preserve the equivalence checks and expected encodings.
- For PQC tests (ML-KEM, ML-DSA, SLH-DSA), preserve runtime capability checks and skip behavior when platform/provider requirements are not met (for example OpenSSL 3.3+ on Linux).
