# Web Security Testing Lab

A deliberately local, educational Flask lab for understanding two common web application weaknesses: SQL injection and cross-site scripting (XSS). Each lesson includes an intentionally vulnerable example beside a safer implementation.

> **Safety boundary:** This lab is designed for your own machine only. It binds to `127.0.0.1`, uses a temporary local SQLite database, contains fictional data, and must not be deployed to a public server or exposed to a shared network.

## Learning objectives

- Understand how unsafe SQL string construction can change a database query.
- Compare unsafe SQL with parameterized queries.
- Understand how untrusted content can become executable markup.
- Compare unsafe rendering with context-aware HTML escaping.
- Practice documenting findings and remediation.

## Requirements

- Python 3.10+
- Flask 3.x

## Setup

```bash
cd projects/web-security-testing-lab
python -m venv .venv
# Windows: .venv\\Scripts\\activate
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser. Stop the server with Ctrl+C.

The app creates a disposable SQLite database in the system temporary directory and inserts fictional sample users on startup.

## Lab exercises

### 1. SQL injection

Open the SQL injection lesson and compare the two search forms.

- The vulnerable demonstration concatenates the supplied search text into a SQL statement.
- The safe demonstration uses a parameterized query.
- Use only the fictional sample data in this local lab. Observe how input is interpreted as SQL in the unsafe example and as data in the safe example.

### 2. Cross-site scripting (XSS)

Open the XSS lesson and submit a harmless text string such as `hello lab`.

- The vulnerable demonstration renders submitted text without HTML escaping.
- The safe demonstration escapes the text before placing it in an HTML context.
- For a controlled demonstration, you may enter a harmless HTML formatting snippet such as `<b>hello</b>` and compare how each page displays it. Do not use payloads targeting other users or external sites.

## Run tests

```bash
python -m unittest -v
```

Tests verify the safe SQL parameterization behavior, safe output escaping, and that the development server configuration is loopback-only.

## Security report template

For each finding, record:

1. **Title and severity:** What is the weakness and why does it matter?
2. **Affected feature:** Which lesson or input is involved?
3. **Evidence:** Describe the harmless local observation.
4. **Root cause:** Identify the unsafe coding pattern.
5. **Remediation:** Explain the safe implementation.
6. **Retest:** Describe how you confirmed the fix.

## Important limitations

This is a deliberately vulnerable teaching application, not a production application or a general-purpose penetration-testing tool. It has no authentication, no real user data, and no external scanning functionality. Do not expose it to the internet, deploy it, or use it to test systems you do not own or have explicit authorization to assess.
