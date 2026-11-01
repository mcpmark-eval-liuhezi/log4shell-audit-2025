# SECURITY-NOTES.md — Log4Shell (CVE-2021-44228)

## Core facts

- **CVE identifier:** CVE-2021-44228 (commonly known as **Log4Shell**)
- **What it is:** A remote code execution vulnerability in Apache Log4j 2. When message lookup substitution is enabled, an attacker who can control log messages or log message parameters can trigger JNDI lookups (e.g. `${jndi:ldap://...}`) that load and execute arbitrary Java code from an attacker-controlled LDAP/RMI server.
- **Severity:** CVSS 3.1 base score **10.0 — CRITICAL**
  - Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
  - Impact: network exploitable, no auth, no user interaction; full compromise of confidentiality, integrity, and availability.
- **Affected versions:**
  - Apache Log4j2 **2.0-beta9 through 2.14.1** (versions `[2.0-beta9, 2.3.1) ∪ [2.4, 2.12.2) ∪ [2.13.0, 2.15.0)`)
  - Also affected ranges per follow-up CVEs: CVE-2021-45046 `[2.0-beta9, 2.3.1) ∪ [2.4, 2.12.3) ∪ [2.13.0, 2.16.0)`; CVE-2021-45105 `[2.0-alpha1, 2.3.1) ∪ [2.4, 2.12.3) ∪ [2.13.0, 2.17.0)`; CVE-2021-44832 `[2.0-beta7, 2.3.1) ∪ [2.4, 2.12.3) ∪ [2.13.0, 2.17.0)`
- **Fixed versions:**
  - **2.15.0** — JNDI lookup behavior disabled by default (fixes CVE-2021-44228; incomplete in some non-default configurations)
  - **2.16.0** — removes JNDI entirely (fixes CVE-2021-45046)
  - **2.17.0** — fixes CVE-2021-45105 and limits JDBC appender JNDI to the `java` protocol only
  - **2.17.1 / 2.12.4 / 2.3.2** — latest hardens for Java 8+ / Java 7 / Java 6 respectively
  - Java 7 should use 2.12.2+ (2.12.3/2.12.4 for later CVEs); Java 6 should use 2.3.1+ (2.3.2 for later CVEs)
- **Scope:** only the `log4j-core` jar is affected; applications using only `log4j-api` without `log4j-core` are not impacted.

## Follow-up Log4j CVEs in the same chain

| CVE | Severity (CVSS 3.x) | Fixed version |
|---|---|---|
| CVE-2021-44228 | 10.0 CRITICAL | 2.15.0 (2.16.0+ recommended) |
| CVE-2021-45046 | 9.0 CRITICAL | 2.16.0 |
| CVE-2021-45105 | 5.9 MEDIUM | 2.17.0 |
| CVE-2021-44832 | 6.6 MEDIUM | 2.17.0 |

## Sources

- NVD — CVE-2021-44228: https://nvd.nist.gov/vuln/detail/cve-2021-44228
- Apache Logging Services — Security page: https://logging.apache.org/security.html
- Apache Software Foundation blog — Apache Log4j CVEs: https://news.apache.org/foundation/entry/apache-log4j-cves
- CISA KEV — Apache Log4j2 Remote Code Execution Vulnerability: https://www.cisa.gov/artifacts/cisa-kev/2021/12/10/apache-log4j2-remote-code-execution-vulnerability
- Rapid7 Vulnerability Database — CVE-2021-44228: https://www.rapid7.com/db/vulnerabilities/cve-2021-44228/

## Remediation summary

1. Upgrade Log4j to 2.17.1+ (Java 8+), 2.12.4 (Java 7), or 2.3.2 (Java 6).
2. Detect vulnerable deployments: scan for `log4j-core` versions and log patterns like `${jndi:ldap://`, `${jndi:rmi://`.
3. Harden temporarily: set `log4j2.formatMsgNoLookups=true` (or `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`), remove `JndiLookup.class`, restrict JNDI to the `java` protocol.
4. Automate dependency scanning with OWASP Dependency-Check, Trivy, Snyk, or CodeQL in CI.
