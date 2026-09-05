# Auditor Engine

A lightweight, local-first static analysis orchestrator designed for freelancers, independent developers, and small agencies to inspect their codebase prior to client handoff.

Auditor Engine unifies SAST analysis, package dependency vulnerability scanning, and hardcoded secret detection into a single run, generating a clean local dashboard and delivery-ready summaries.

---

## What It Is (and What It Is Not)

> **Important Security & Scope Disclaimer**
> 
> Auditor Engine is an automated baseline quality gate, **not an infallible security guarantee**. 
> 
> * **Not a replacement for manual penetration testing:** Automated static analysis cannot uncover complex business logic flaws, authorization bypasses, architectural misconfigurations, or novel zero-day exploits.
> * **Not an absolute security certification:** Passing an audit means no known patterns or reported CVEs matched your codebase under the configured rule profiles. It does not certify that your application is 100% exploit-proof.
> * **Purpose:** It serves as a rapid, friction-free pre-delivery checkpoint to prevent accidental credential leaks, outdated vulnerable dependencies, and common OWASP Top 10 vulnerabilities from reaching client repositories.

---

## Key Features

* **100% Local-First:** Your source code never leaves your computer. No cloud uploads, no external data processing, and no third-party data retention.
* **Unified Toolchain:** Runs Semgrep rulesets alongside ecosystem-native package scanners (`npm audit`, `composer audit`) and entropy-based regex credential detection in a single command.
* **Smart Secret Filtering:** Entropy-based pattern matching filters out common mock identifiers, routing keys, and config placeholders to reduce noise.
* **Interactive Local Dashboard:** Clean browser interface running locally on your machine with categorization by critical blockers vs. non-blocking observations.
* **Zero Infrastructure Overhead:** Requires no complex CI/CD pipeline setup or remote tokens to execute.

---

## Prerequisites

Before running Auditor Engine, ensure the following utilities are installed and available in your system `$PATH`:

* [Node.js](https://nodejs.org/) (v18 or higher recommended)
* [Semgrep CLI](https://semgrep.dev/docs/getting-started/) (`pip install semgrep` or via brew)
* Package managers relevant to your target environment (`npm` for Node.js projects, `composer` for PHP projects)

---

## Quick Start

### 1. Clone & Install Dependencies

```bash
git clone [https://github.com/your-username/auditor-engine.git](https://github.com/your-username/auditor-engine.git)
cd auditor-engine
npm install
```

### 2. Launch the Local Web UI

Start the local server and navigate to `http://localhost:3000`:

```bash
npm start
```

From the dashboard:
1. Select **Local Directory** or upload a **.ZIP** archive.
2. Choose your environment profile: `Node.js`, `PHP / Laravel`, or `Static Web`.
3. Click **Run Security Audit** to review findings directly in the browser.

### 3. Run Directly via CLI

You can also run audits headlessly via the terminal:

```bash
node Orchestrator.js <path-or-zip> <node|php|static_web>
```

Example:

```bash
node Orchestrator.js ./my-express-api node
```

Upon completion, execution results will be written to `scan-report.json`.

---

## Generating the Delivery Report

To compile an exportable HTML delivery certificate from your latest audit:

```bash
node ReportGenerator.js "Client Project Name"
```

This outputs `Delivery-Certificate.html` containing:
* Executive pass/review status badge.
* Total blocker and observation metrics.
* Filtered findings categorized with OWASP and CWE classifications.

---

## Supported Environments

| Environment | SAST Engine | Dependency Scanner | Secret Detection |
| :--- | :--- | :--- | :--- |
| **Node.js** | Semgrep (`p/nodejs`, `p/javascript`) | `npm audit` | Shannon Entropy + Regex |
| **PHP / Laravel** | Semgrep (`p/php`) | `composer audit` | Shannon Entropy + Regex |
| **Static Web** | Semgrep (`p/javascript`, `p/default`) | N/A | Shannon Entropy + Regex |

---

## License

This project is licensed under the AGPLv3(LICENSE).
