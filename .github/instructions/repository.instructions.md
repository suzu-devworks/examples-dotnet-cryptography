---
description: Repository-specific constraints for this codebase.
applyTo: "**"
---

- Never commit or stage `assets/` (private keys/certs and `.password` artifacts may exist there).
- Do not manually edit `src/Examples.Cryptography.Xml.Tests/generated/**`.
- For XML-derived type changes, edit `src/Examples.Cryptography.Xml.Tests/Resources/XAdES/*.xsd` and/or `src/Examples.Cryptography.Xml.Tests/XmlSampleGenerator.Build.targets`.
- Run `dotnet tool restore` before build/test flows that can trigger `dotnet xscgen`.
