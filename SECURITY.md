# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.x (current) | ✅ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by opening a [GitHub Security Advisory](https://github.com/obalogunolabimpeoluwakanyinsol-ai/soroban-passkey-account/security/advisories/new) on this repository. This keeps the report confidential until a fix is ready.

Include:
- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The potential impact
- Any suggested fix if you have one

You will receive an acknowledgment within 48 hours. We aim to produce a fix and coordinated disclosure within 90 days.

## Known limitations (by design)

These are documented design decisions, not vulnerabilities:

- **Unrecoverable account if all passkeys are lost.** This is a fundamental consequence of removing the seed phrase. Social recovery is a planned v2 feature.
- **Counter=0 compatibility mode.** Credentials that always report counter=0 are exempt from counter checking, per the WebAuthn spec. This is intentional and documented.
- **No on-chain credential discovery.** The caller must know which `credential_id` to present. There is no way to enumerate credentials from outside the contract.
- **Origin validation is exact-match.** Subdomains of the allow-listed origin are not accepted. This is intentional — exact matching is the strictest and safest default.

## Scope

In scope for security reports:
- Logic errors in `__check_auth` (signature verification, counter checking, origin validation)
- Storage manipulation that bypasses authentication
- Denial-of-service vectors that permanently brick accounts

Out of scope:
- Issues in Soroban's native `secp256r1_verify` host function (report those to the Stellar core team)
- Social engineering attacks on WebAuthn (these are user/browser issues, not contract issues)
