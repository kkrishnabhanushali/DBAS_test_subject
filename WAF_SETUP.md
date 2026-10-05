# 🛡️ Web Application Firewall (WAF) Setup & Guide

This project includes a **built-in Application-Level WAF** and supports deployment behind **Enterprise/Cloud WAFs** (such as Cloudflare WAF or AWS WAF).

---

## 1. Built-in Application WAF (Already Installed)

The application includes an embedded WAF middleware located at [`src/middleware/waf.js`](file:///Users/kkrishnabhanushali/Documents/testsubject/src/middleware/waf.js) that inspects all incoming requests before they reach your application logic or database.

### Features
- **SQL Injection (SQLi) Defense**: Detects `UNION SELECT`, `' OR '1'='1`, subqueries, SQL comments, and time-based payloads.
- **Cross-Site Scripting (XSS) Defense**: Blocks script tags, event handlers (`onerror=`, `onload=`), `javascript:` pseudo-protocols, and malicious SVG/HTML objects.
- **Path Traversal / Local File Inclusion (LFI)**: Blocks `../`, `..%2f`, `/etc/passwd`, and Windows system file references.
- **Remote Code Execution (RCE)**: Blocks command injection patterns (piping to shell commands like `sh`, `bash`, `curl`, `wget`, `nc`).
- **Prototype Pollution Defense**: Intercepts `__proto__` and `constructor.prototype` tampering in request payloads.
- **Malicious Scanner Blocking**: Automatically drops requests from reconnaissance tools like `sqlmap`, `nikto`, `acunetix`, `dirbuster`, `gobuster`, `nmap`, etc.
- **Incident Audit Logging**: Generates a unique incident ID and logs the attack type, IP address, matched pattern, and targeted parameter.

### Configuration (`.env`)

You can configure the WAF behavior in your `.env` file:

```env
# Enable or disable the WAF (default: true)
WAF_ENABLED=true

# Mode: 'block' (default - responds with 403) or 'monitor' (audit only, headers logged)
WAF_MODE=block
```

### Testing the Built-in WAF

Run the automated attack test suite:
```bash
npm run test:waf
```

---

## 2. Cloudflare WAF (Recommended for Production)

Putting your application behind **Cloudflare** provides edge-level DDoS protection, bot management, and managed OWASP rulesets before malicious traffic even touches your server.

### Step 1: Add your domain to Cloudflare
1. Sign up or log in to [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Click **Add Site** and enter your domain name.
3. Choose the Free or Pro plan.

### Step 2: Configure DNS
1. Point your domain's `A` or `CNAME` record to your server's IP address.
2. Ensure the **Proxy status** toggle is set to **Proxied (Orange Cloud)**.

### Step 3: Enable WAF Rulesets
1. In Cloudflare, navigate to **Security** → **WAF**.
2. Under **Managed Rules**:
   - Enable **Cloudflare Managed Ruleset** (Defends against CVEs and zero-days).
   - Enable **Cloudflare OWASP Core Ruleset** (Paranoia Level 1 or 2).
3. Under **Bots**:
   - Turn on **Bot Fight Mode** to challenge automated scrapers and credential stuffers.
4. Under **Rate Limiting Rules**:
   - Add a rule to throttle suspicious traffic (e.g., more than 50 requests per 10 seconds per IP).

### Step 4: Configure Node.js to Trust Cloudflare Proxies
In `server.js`, `app.set('trust proxy', 1);` is already enabled. When behind Cloudflare, client IPs are accurately extracted from the `cf-connecting-ip` header.

---

## 3. AWS WAF (For AWS CloudFront / ALB)

If hosting on AWS (EC2, ECS, or Elastic Beanstalk):

1. Go to **AWS WAF & Shield** in the AWS Console.
2. Click **Create web ACL**:
   - Choose Resource type: **Amazon CloudFront** or **Regional resources (Application Load Balancer)**.
3. Add **AWS Managed Rules**:
   - **Core rule set (CRS)**: Comprehensive protections for OWASP Top 10.
   - **Known bad inputs**: Detects invalid input and host header exploits.
   - **SQL database**: Specialized rules for SQL injection mitigation.
   - **Amazon IP reputation list**: Blocks IPs associated with bots and scanners.
4. Set Default Action to **Allow** and associate the Web ACL with your ALB or CloudFront distribution.

---

## 4. NGINX + ModSecurity / Coraza (Self-Hosted Reverse Proxy)

If you run your own VPS (Ubuntu/Debian) with NGINX in front of Node.js:

```nginx
# /etc/nginx/sites-available/your-app.conf
server {
    listen 80;
    server_name yourdomain.com;

    # ModSecurity WAF integration
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Defense-in-Depth Summary

| Layer | Component | Protection |
| :--- | :--- | :--- |
| **Edge / DNS** | Cloudflare / AWS WAF | Volumetric DDoS, Bot mitigation, Geo-blocking |
| **Reverse Proxy** | Nginx / ModSecurity | Request buffering, TLS termination, protocol compliance |
| **Application WAF** | `src/middleware/waf.js` | SQLi, XSS, Path Traversal, RCE, Prototype Pollution |
| **HTTP Headers** | Helmet | CSP, HSTS, Frameguard, X-Content-Type-Options |
| **Rate Limiter** | `express-rate-limit` | Brute force, credential stuffing, DoS |
| **Integrity** | `csrf-csrf`, `hpp` | CSRF double-submit cookies, parameter pollution |