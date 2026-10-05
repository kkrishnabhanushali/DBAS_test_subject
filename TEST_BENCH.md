# 🧪 Vulnerability Scanner Test Bench (Benchmark Guide)

This module provides a controlled, sandboxed suite of real-world web application vulnerabilities (covering the **OWASP Top 10** / **CWE Top 25**) specifically designed to validate, benchmark, and calibrate your vulnerability scanner.

---

## ⚙️ How to Activate

1. Open your `.env` file and set:
   ```env
   ENABLE_TEST_BENCH=true
   ```
2. Restart your Node.js server:
   ```bash
   npm start
   # or npm run dev
   ```
3. When active, the server startup banner will display:
   ```text
   ⚠️  SCANNER TEST BENCH ACTIVE (/api/test-bench)
   ```

---

## 🎯 Ground Truth Manifest

Point your scanner at `http://localhost:3000/api/test-bench/` (or retrieve the machine-readable manifest at `GET /api/test-bench/manifest`).

| Vulnerability Category | CWE | Target Endpoint | Method | Test Parameter | Expected Scanner Result |
| :--- | :---: | :--- | :---: | :---: | :--- |
| **Reflected XSS** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `/api/test-bench/search` | `GET` | `q` | Reflects unfiltered HTML/JS payloads in `text/html`. |
| **SQL Injection** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `/api/test-bench/items` | `GET` | `id` | Generates SQL syntax errors and leaks query structure on single quotes/UNION. |
| **Path Traversal** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `/api/test-bench/view-file` | `GET` | `file` | Permits directory traversal (`../../package.json`) and file disclosure. |
| **Open Redirect** | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `/api/test-bench/redirect` | `GET` | `url` | Unvalidated 302 redirection to arbitrary external domains. |
| **Information Leak** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `/api/test-bench/debug-info` | `GET` | *(None)* | Exposes internal environment variables, versions, and config file names. |
| **Insecure Direct Object Reference (IDOR)** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | `/api/test-bench/user-record/:id` | `GET` | `id` (path) | Returns confidential user data without authentication or ownership check. |
| **Permissive CORS** | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | `/api/test-bench/cors-data` | `ALL` | *(Origin header)* | Echoes arbitrary origins with `Access-Control-Allow-Credentials: true`. |

---

## 🔍 How to Test with Your Scanner

1. **Automated Crawl**: Configure your scanner to crawl from root URL:
   ```text
   http://localhost:3000/api/test-bench/
   ```
2. **Direct Endpoint Testing**: If your scanner accepts individual endpoint targets, feed it the endpoints listed above.
3. **WAF Interaction Testing**:
   - **Scanner vs Application**: With `ENABLE_TEST_BENCH=true`, WAF checks are bypassed on `/api/test-bench/` so your scanner can directly hit the vulnerable endpoints.
   - **Scanner vs WAF**: If you want to test whether your WAF successfully blocks your scanner, target the production routes (e.g., `/api/tasks`, `/api/csrf-token`) or run `npm run test:waf`.
