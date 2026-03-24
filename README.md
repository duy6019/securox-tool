# 🛡️ Securox Security Orchestrator

**Securox** is a lightweight, high-performance security scanning orchestrator built with [Bun](https://bun.sh/). It unifies three powerful open-source security tools into a single CLI and GitHub Action:

- **Opengrep (SAST):** Static Analysis Security Testing for 30+ languages.
- **Trivy (SCA):** Software Composition Analysis for vulnerable dependencies.
- **Gitleaks (Secrets):** Scanning for hardcoded secrets and credentials.

---

## 🚀 Key Features

- **One-Command Install:** High-speed binary downloading for MacOS (Intel/ARM), Linux, and Windows.
- **Offline-First:** Bundled with default security rules; works in air-gapped or restricted CI environments.
- **GitHub Action Native:** Includes a built-in caching system to bypass GitHub API rate limits (403 errors).
- **Unified Reporting:** Consistent JSON, SARIF, and Terminal outputs for all scanners.
- **Zero-Config Defaults:** Optimized for modern TypeScript/JavaScript, Python, Go, and Ruby projects.

---

## 💻 Local Setup

### 1. Prerequisites
You need [Bun](https://bun.sh/) installed on your machine.
```bash
curl -fsSL https://bun.sh/install | bash
```

### 2. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/your-username/securox.git
cd securox
bun install
```

### 3. Download Security Binaries
Since Securox orchestrates external tools, you need to download the required binaries (Opengrep, Trivy, Gitleaks):
```bash
bun run scripts/download-binaries.ts
```

### 4. Basic Usage
Run a full security scan on the current directory:
```bash
# Using the source code
bun run src/index.ts scan

# Or build a standalone binary
bun run build:bin
./dist/securox scan
```

---

## ⚙️ Configuration

Create a `.securox.yml` file in your project root to customize the scan logic:

```yaml
# .securox.yml
scanners:
  sast: true    # Enable/Disable Opengrep
  sca: true     # Enable/Disable Trivy
  secrets: true # Enable/Disable Gitleaks

# Only fail if vulnerabilities >= High are found
severity-threshold: high

# Files/folders to skip
exclude:
  - "node_modules/"
  - "*.test.ts"
  - "dist/"
```

---

## 🤖 GitHub Action Integration

Securox is designed to run seamlessly in GitHub Actions. Add it to your workflow (`.github/workflows/security.yml`):

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Runs Securox with automatic binary caching
      - name: Securox Scan
        uses: ./ # Use your repo path here
        with:
          fail-on: 'critical'
          format: 'terminal'
```

---

## 🧪 Testing

Securox comes with a robust test suite:

- **Unit Tests:** Verify mapping logic and configurations (Fast, no binaries needed).
  ```bash
  bun test tests/unit
  ```
- **Integration Tests:** Verify real scanner execution against vulnerable fixtures (Requires binaries).
  ```bash
  bun test tests/integration
  ```

---

## 🛡️ License
Open-source under the MIT License.
