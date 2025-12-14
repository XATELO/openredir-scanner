<p align="center">
  <img src="logo.png" alt="ReddeZeress Logo" width="450"/>
</p>

# ReddeZeress — Advanced Open Redirect Scanner

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**v2.0 Smart Network Edition**

ReddeZeress is a highly specialized tool designed to detect Open Redirect vulnerabilities. Unlike standard scanners that only check parameters using high-level libraries, ReddeZeress uses **Path Discovery**, **Raw HTTP Packet Construction** (to bypass WAFs/normalization), and **Intelligent DOM/Header Analysis**.

## ⚡ Key Features

*   **Smart Fuzzing Engine:** Automatically generates attack vectors for both parameters (`?next=`) and URL paths (`/login?next=`).
*   **Raw Request Engine:** Uses low-level request preparation to bypass URL-encoding protections that often block standard scanners.
*   **Deep Analysis:**
    *   **Header:** Validates `Location` headers against the payload marker.
    *   **DOM:** Detects JavaScript sinks (`window.location`, `meta-refresh`) even in 200 OK responses.
*   **WAF Evasion:** Built-in Jitter (random delays) and Auto-Retry logic to handle rate-limiting and unstable connections.
*   **False Positive Filtering:** Automatically filters out WAF block pages, Captchas, and innocuous reflections.

## 📦 Installation

ReddeZeress requires Python 3.8+.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/XATELO/openredir-scanner.git
    cd openredir-scanner
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Usage

### Single Target Scan
Perfect for quick checks. The tool will fuzz parameters automatically.
```bash
python openredir.py -u https://example.com


### Bulk Scan
Scan a list of URLs from a file.
```bash
python openredir.py -l targets.txt -t 20


### Verbose Mode (Debug)
Use -v to see all 3xx redirects (even safe ones) and connection errors. Useful for debugging WAFs.
```bash
python openredir.py -u https://example.com -v



## ⚙️ Options
Flag	Description	Default
-u, --url	Single target URL	None
-l, --list	File containing list of URLs	None
-t, --threads	Number of concurrent threads	20
-v, --verbose	Show debug info (all redirects/errors)	False


## ⚠️ Legal Disclaimer
This tool is intended for educational purposes and authorized security testing only. The authors are not responsible for any misuse or damage caused by this program.