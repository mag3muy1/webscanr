# WebScanr 🔍

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
webscanr/
│── main.py               # Entry point: handles CLI and orchestrates scans
│
├── payloads/
│   └── XSSPayload.txt    # Example XSS payloads
│
├── scanner/
│   ├── __init__.py
│   ├── payload_manager.py # Load and manage payloads
│   ├── tech_scanner.py    # WebTech-based tech fingerprinting
│   ├── form_scanner.py    # Extracts and submits forms
│   ├── xss_scanner.py     # Reflected XSS scanning
│   ├── popup_scanner.py   # Popup-based XSS detection (Selenium)
│   └── dom_scanner.py     # DOM-based injection detection
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
python3 main.py --url http://target.com --scan all --report pdf
```

### Options

| Flag        | Description                                                 |
| ----------- | ----------------------------------------------------------- |
| `--url`     | Target URL                                                  |
| `--scan`    | Select scan type: `xss`, `sqli`, `misconfig`, `tech`, `all` |
| `--report`  | Output format: `json`, `pdf`, `docx`                        |
| `--payload` | Custom payload file                                         |
| `--threads` | Number of concurrent threads                                |

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
