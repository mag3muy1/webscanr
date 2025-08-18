# WebScanr 🔍
                                                  
                                                       =======================
                                                           w e b s c a n r  ᵛ¹
                                                       =======================

**WebScanr** is an open-source automated web vulnerability scanner designed to detect common web application vulnerabilities, map them to CVEs, and generate clear, actionable reports.
It is built to be a lightweight yet powerful alternative to commercial scanners like **Acunetix** and **Burp Suite**, optimized for **speed, accuracy, and usability**.

---

## ✨ Features

* **Vulnerability Detection**

  * SQL Injection (SQLi) – error-based parameter scanning
  * Cross-Site Scripting (XSS) – reflected, popup-based, and DOM-based
  * Outdated Components – fingerprints web technologies and checks versions
  * Security Misconfigurations – checks headers, exposed paths, expired SSL, etc.

* **CVE Integration**

  * Real-time CVE updates via **National Vulnerability Database (NVD)**
  * Offline caching for local scans
  * Maps findings to CVEs with **CVSS severity ratings**

* **Performance Optimization**

  * Asynchronous HTTP requests
  * Threading & multiprocessing
  * Selective payload fuzzing for efficiency

* **Automated Reporting**

  * Generates reports using **Hugging Face LLM API**
  * Export formats: **Word (.docx)**, **JSON (.json)**, **PDF (.pdf)**
  * Includes: summary, PoCs, step-by-step remediation, severity ratings, and business impact

* **CLI Driven**

  * Intuitive command-line interface (via `argparse`)
  * Clean terminal output
  * Works on **any modern Linux distribution**

* **Custom Wordlists**

  * Supports external payloads from **SecLists**, **FuzzDB**, or custom files

---

## 📂 Project Structure

```
webscanr
├── main.py                 # Entry point: CLI and scan orchestration
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
├── ExposedPath.txt         # Payloads for exposed path scanning
├── SQLPayload.txt          # SQL injection payloads
├── XSSPayload.txt          # XSS payloads
│
├── fetch_version/          # Version fetchers for outdated components
│   ├── bootstrapfetch.py
│   ├── electronfetch.py
│   ├── momentfetch.py
│   ├── reactfetch.py
│   ├── tensorfetch.py
│   └── __init__.py
│
├── scanner/                # Core scanning modules
│   ├── __init__.py
│   ├── ai_helper.py        # HuggingFace LLM integration for reporting
│   ├── form_scanner.py     # Extract and submit forms
│   ├── misconfig_scanner.py# Misconfiguration checks (headers, SSL, files)
│   ├── nvd_checker.py      # NVD CVE integration
│   ├── outdated_checker.py # Compare versions against latest
│   ├── payload_manager.py  # Load/manage payloads
│   ├── report_gen.py       # Report generation (Word, PDF, JSON)
│   ├── sql_scanner.py      # SQL Injection scanner
│   ├── tech_scanner.py     # WebTech-based fingerprinting
│   ├── web_crawl.py        # Crawler for internal links
│   ├── xss_scanner.py      # Reflected XSS detection
│   └── templates/          # Report templates
│       ├── pdf_template.html
│       └── word_template.docx
│
├── reports/                # Generated reports
│   ├── finalized-reporting.pdf
│   ├── hf-token-new-model.docx
│   ├── testing.pdf
│   ├── webscanr_report_*.{pdf,docx,json}
│   └── ...
│
└── __pycache__/            # Python cache files

```

---

## ⚡ Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/webscanr.git
cd webscanr

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
python3 main.py http://target.com --all --report-format pdf --report-name name_goes-here
```

---

### CLI Options

| Argument            | Description                            |
| ------------------- | -------------------------------------- |
| `url`               | **(positional)** Target URL            |
| `-h, --help`        | Show help message and exit             |
| `--threads THREADS` | Number of threads (**default:** 10)    |
| `--stop-on-success` | Stop when first vulnerability is found |

#### 🔎 Scan Options

| Flag                    | Description                                                    |
| ----------------------- | -------------------------------------------------------------- |
| `--all`                 | Run all available scans                                        |
| `--tech`                | Run technology fingerprinting                                  |
| `--check-outdated`      | Check if detected technologies are outdated                    |
| `--xss`                 | Run reflected XSS scan                                         |
| `--dom`                 | Run DOM-based XSS detection (Selenium)                         |
| `--sqli`                | Run SQL injection scan                                         |
| `--check-misconfig`     | Run misconfiguration checks (headers, SSL, exposed files)      |
| `--crawl`               | Crawl and list internal pages                                  |
| `--scan-crawled`        | Scan all crawled pages with enabled scans (XSS, DOM XSS, SQLi) |
| `--max-pages MAX_PAGES` | Maximum number of pages to crawl (**default:** 30)             |
| `--nvd-check`           | Check detected technologies against NVD                        |

#### 📝 Reporting Options

| Flag                              | Description                                            |
| --------------------------------- | ------------------------------------------------------ |
| `--report-format {word,pdf,json}` | Generate report in the specified format                |
| `--report-name REPORT_NAME`       | Specify the output report filename (without extension) |
| `--stdout`                        | Print output as JSON in terminal                       |
| `--verbose`                       | Show verbose output when using `--stdout`              |


---

## 📊 Example Report

A generated report includes:

* Executive summary
* Technical findings with PoCs
* Severity ratings (CVSS-based)
* Business impact analysis
* Remediation steps

---

## 🔒 Non-Functional Requirements

* **Portability**: Runs on Linux without commercial dependencies
* **Open Source**: Released under **MIT License**
* **Extensibility**: Modular structure to easily add new scanners, formats, or integrations


---

## 🤝 Contributing

Contributions are welcome! Please fork the repository, create a branch, and submit a pull request.

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
