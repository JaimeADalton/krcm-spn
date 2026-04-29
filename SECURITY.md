# Security Policy

KRCM-SPN is an experimental cryptographic construction. It is not a replacement for audited, standardized schemes such as AES-GCM, ChaCha20-Poly1305, age, GnuPG, or libsodium. Do not use it to protect production data, regulated data, financial secrets, credentials, or any information whose compromise would cause harm. The project is intended for research, experimentation, implementation practice, and review.

## Supported Versions

The initial public release is `0.1.0`. The v4 container is supported for compatibility. The v5 container is supported for experimentation and review.

## Reporting

Report vulnerabilities through the repository issue tracker or by contacting the maintainer privately if a public report would expose users to avoidable risk. Include the affected version, platform, reproduction steps, and whether the issue affects v4, v5, CLI behavior, or parsing.

## Non-Goals

This project does not provide a security guarantee for sensitive data and has not received an external audit.
