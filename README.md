# Secure Application Development - Project 2026

A PHP web application built for the **Secure Application Development** module, demonstrating 10 common security vulnerabilities and their mitigations.

## Features

- User authentication (login, registration, logout)
- Admin dashboard with login event auditing
- Password change with CSRF protection
- Ping utility (command injection demo)
- File viewer (directory traversal demo)
- Session management with inactivity/absolute timeouts
- Brute-force protection with IP-based rate limiting

## Security Vulnerabilities Mitigated

| # | Vulnerability | Severity | OWASP | CWE |
|---|---|---|---|---|
| 1 | SQL Injection | Critical | A03:2021 | CWE-89 |
| 2 | Reflective XSS | High | A03:2021 | CWE-79 |
| 3 | Persistent XSS | High | A03:2021 | CWE-79 |
| 4 | Session Fixation | High | A07:2021 | CWE-384 |
| 5 | Command Injection | Critical | A03:2021 | CWE-78 |
| 6 | Directory Traversal | High | A01:2021 | CWE-22 |
| 7 | Insufficient Session Management | High | A01:2021 | CWE-285 |
| 8 | Cross-Site Request Forgery (CSRF) | Medium | A01:2021 | CWE-352 |
| 9 | Brute-Force (Registration) | Medium | A07:2021 | CWE-307 |
| 10 | Page Caching | Low | A04:2021 | CWE-525 |

## Tech Stack

- PHP (procedural)
- MySQL / MySQLi
- HTML/CSS
- XAMPP

## Setup

1. Install [XAMPP](https://www.apachefriends.org/)
2. Clone this repo into `htdocs/`
3. Start Apache and MySQL from the XAMPP control panel
4. Create a MySQL user `TEST` with no password (or update `includes/dbh.inc.php`)
5. Navigate to `http://localhost/Project26/`
6. Click **Create / Reset Database & Table** to initialise the database

## Default Accounts

| Role | Username | Password |
|---|---|---|
| Admin | admin | AdminPass1! |
| User | user1 | Password1! |
