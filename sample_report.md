# Security Findings Dashboard

- **Sources aggregated:** 4
- **Total findings:** 11 (8 HIGH, 2 MEDIUM, 1 LOW, 0 UNKNOWN)
- **Total risk score:** 91

## By Source (highest risk first)

| Source | Findings | HIGH | MEDIUM | LOW | Risk Score |
|---|---|---|---|---|---|
| Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | 7 | 5 | 2 | 0 | 60 |
| google.com | 2 | 1 | 0 | 1 | 11 |
| Cloud-IAM-Policy-Auditor/sample_policies/full_admin_example.json | 1 | 1 | 0 | 0 | 10 |
| JWT-Security-Analyzer/sample_tokens/weak_secret_token.txt | 1 | 1 | 0 | 0 | 10 |

## All Findings

| Severity | Source | Summary |
|---|---|---|
| HIGH | Cloud-IAM-Policy-Auditor/sample_policies/full_admin_example.json | Full administrator access: Action "*" + Resource "*" in a single Allow statement. |
| HIGH | google.com | No SPF record found — nothing tells receiving mail servers which hosts are authorized to send email for this domain, making it easy to spoof the From address. |
| HIGH | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | Pipes a remotely fetched script directly into a shell with no integrity check — a compromised download or MITM runs arbitrary code during the build. |
| HIGH | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | ADD fetches a remote URL at build time with no checksum verification. |
| HIGH | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | ENV "API_KEY" bakes a secret-like value directly into an image layer — recoverable by anyone with the image via `docker history`/`docker inspect`, even from an earlier build stage. |
| HIGH | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | ARG "DB_PASSWORD" bakes a secret-like value directly into an image layer — recoverable by anyone with the image via `docker history`/`docker inspect`, even from an earlier build stage. |
| HIGH | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | chmod 777 grants read/write/execute to every user in the image — overly permissive. |
| HIGH | JWT-Security-Analyzer/sample_tokens/weak_secret_token.txt | The signature validates against a common/weak secret ("secret") from a small built-in wordlist — anyone can forge arbitrary tokens signed with this secret. |
| MEDIUM | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | No USER instruction in the final stage (or it's explicitly root) — the container runs as root by default, widening the blast radius of a container-escape or RCE vulnerability. |
| MEDIUM | Dockerfile-Security-Linter/sample_dockerfiles/insecure_example/Dockerfile | Base image "node" is unpinned (no tag, or ":latest") — the image can change unexpectedly between builds, breaking reproducibility and supply-chain traceability. |
| LOW | google.com | No DKIM record found under 7 common selector names (default, selector1, selector2, google, k1, s1, dkim). DKIM may still be configured under a non-standard selector this check doesn't know about — this is not conclusive. |
