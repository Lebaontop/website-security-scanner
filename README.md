# Website Security Scanner

A lightweight Python tool that checks the basic transport security of any website and gives it a score out of 100, with a suggested fix for every problem it finds. Paste a link into the web page (or the terminal) and get a report in seconds.

## Features

- **HTTPS check**: does the site open over HTTPS?
- **SSL certificate check**: issuer, expiry date, days remaining, and the exact reason when a certificate is rejected (expired, self-signed, hostname mismatch).
- **HTTP to HTTPS redirect**: does plain HTTP send visitors to the secure version?
- **HSTS check**: is the `Strict-Transport-Security` header present with a long enough `max-age`?
- **Security headers**: `Content-Security-Policy`, `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`.
- **Score and grade** (A to F) with a fix suggestion for each failed check.
- **Two ways to use it**: a local web page, or the command line.

## Scoring

| Check                    | Points |
|--------------------------|--------|
| HTTPS                    | 20     |
| SSL certificate          | 20     |
| HTTP to HTTPS redirect   | 15     |
| HSTS                     | 15     |
| Content-Security-Policy  | 10     |
| X-Frame-Options          | 8      |
| X-Content-Type-Options   | 6      |
| Referrer-Policy          | 6      |

If HTTPS itself is not working, the checks that depend on it are marked **SKIP** instead of failing again, so a site is never penalized twice for the same problem.

## Installation

Requires Python 3.8 or newer.

```bash
git clone https://github.com/Lebaontop/website-security-scanner.git
cd website-security-scanner
pip install -r requirements.txt
```

## Usage

**Web page** (paste a link and press Scan):

```bash
python app.py
```

Your browser opens at `http://127.0.0.1:8000`. The server only listens on your own computer.

**Command line**:

```bash
python scanner.py example.com     # scan one site
python scanner.py                 # paste links one after another (q to quit)
```

Example output:

```
Scan report: example.com
------------------------------------------------------------
[PASS] Site supports HTTPS
[PASS] Certificate is valid - issuer: ..., expires: ... (... days left)
[PASS] HTTP redirects to HTTPS
[FAIL] HSTS header is missing (browsers are not forced to use HTTPS)
       Fix: Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains
...
Security score: 78/100 (grade B)
```

## Project structure

```
scanner.py        scan engine (checks, scoring, command-line interface)
app.py            local web page built on Python's standard library
requirements.txt  dependencies (requests)
```

## Limitations

- The score only reflects what this tool checks. A high score does not mean a site is fully secure.
- Sites on the browsers' **HSTS preload list** may be protected even when the redirect or header check fails, because the tool does not read that list.
- Only public information is read (certificate and response headers). The tool does not test for vulnerabilities such as SQL injection or XSS.

## Responsible use

Scan your own websites or public sites. Do not use this tool to probe systems you do not have permission to test.

## Ideas for future work

- Cookie flags check (`Secure`, `HttpOnly`, `SameSite`)
- Scan a list of sites from a file
- Store results in a database and show history
- Export the report as PDF or HTML
