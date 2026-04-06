# Interview Prep - Security Vulnerability Mitigation Project

## Interview Format
- **Date:** Monday 13 April 2026
- **Assessed on:** Vulnerability Knowledge + Mitigation Knowledge
- **High grade:** Correctly name, classify, explain root cause, explain why your fix works, and note tradeoffs

---

## 1. SQL Injection

**Location:** includes/login.inc.php
**CWE:** CWE-89 | **OWASP:** A03:2021 - Injection

**Root cause:** User input was concatenated directly into the SQL query. Passwords were stored in plaintext and compared in the SQL query itself, so `' OR Sleep(3); --` could alter the query logic.

**Your fix:**
- Prepared statement with `?` placeholder: `SELECT * FROM sapusers WHERE user_uid = ?`
- `bind_param("s", $uid)` ensures input is treated as data, not code
- Password removed from SQL entirely — fetched by username only
- `password_verify($pwd, $hashedPwdCheck)` compares in PHP against bcrypt hash
- Registration hashes with `password_hash($pwd, PASSWORD_BCRYPT)`

**Why it works:** Prepared statements separate SQL structure from data. The database engine compiles the query before inserting the value, so injected SQL is never executed. Password verification in PHP means the password is never part of the query.

**Tradeoffs:** Slightly more code than string concatenation. Prepared statements add negligible overhead. Bcrypt hashing adds ~100ms per hash, but this is intentional to slow brute-force attacks.

**If asked "why not just escape the input?":** Escaping is error-prone and relies on the developer remembering every time. Prepared statements are structural — they make injection impossible by design.

---

## 2. Reflective XSS

**Location:** includes/login.inc.php
**CWE:** CWE-79 | **OWASP:** A03:2021 - Injection

**Root cause:** `cleanChars()` returned the value untouched — no sanitization. On failed login, the username was reflected directly into the error message, allowing `<script>alert('XSS Hole')</script>` to execute.

**Your fix:**
- `cleanChars()` now calls `RemoveXSS()`
- RemoveXSS strips null bytes and control characters
- Decodes HTML entity obfuscation (hex `&#x41;` and decimal `&#65;`) back to literal characters
- Recursively strips dangerous HTML tags, event handlers, and `javascript:` protocol strings

**Why it works:** Attackers encode payloads to bypass filters. RemoveXSS decodes them first, then strips dangerous content. The recursive loop handles nested obfuscation like `<scr<script>ipt>`.

**Tradeoffs:** RemoveXSS is a blacklist approach — it blocks known dangerous patterns rather than encoding all output. New attack vectors could theoretically bypass it. However, it provides strong defence-in-depth by handling multiple encoding layers.

**If asked "why not htmlspecialchars?":** Assignment constraint — we were told not to use it.

---

## 3. Persistent (Stored) XSS

**Location:** admin.php
**CWE:** CWE-79 (Stored XSS) | **OWASP:** A03:2021 - Injection

**Root cause:** User IDs from login attempts were stored in the database and displayed in admin.php without sanitization. The payload `' onmouseover=alert(1); x='` persisted in the database and executed whenever an admin viewed the page.

**Your fix:**
- All 5 database fields (`event_id`, `ip`, `timeStamp`, `user_id`, `outcome`) are passed through `RemoveXSS()` before being inserted into HTML

**Why it works:** Even if malicious data was stored before the fix, RemoveXSS neutralises it at render time. Event handlers like `onmouseover=` are stripped regardless of what's in the database.

**Tradeoffs:** Output sanitization is a last line of defence. Ideally you'd also sanitize on input, but output encoding catches anything that slips through.

**Key distinction from Reflective XSS:** Reflective = payload comes from the current request and is immediately reflected. Persistent = payload is stored in the database and executes later, potentially affecting other users (like an admin).

---

## 4. Session Fixation

**Location:** includes/login.inc.php (after authentication)
**CWE:** CWE-384 | **OWASP:** A07:2021 - Identification and Authentication Failures

**Root cause:** The PHPSESSID remained the same before and after login. An attacker could set a known session ID in a victim's browser, wait for them to log in, then use that same session ID to hijack their authenticated session.

**Your fix:**
- `session_regenerate_id(true)` immediately after successful authentication
- Placed BEFORE setting session variables

**Why it works:** `session_regenerate_id()` creates a completely new session ID. The `true` parameter deletes the old session file on the server. The attacker's pre-set session ID becomes invalid. Because it runs before `$_SESSION['u_id']` is set, authenticated data is only associated with the new session.

**Tradeoffs:** Minimal — one extra function call. Slight server overhead to create a new session file and destroy the old one. No impact on user experience.

**If asked "what's the attack scenario?":**
1. Attacker visits the site, gets a PHPSESSID
2. Attacker tricks victim into using that same session ID (e.g., via a crafted link)
3. Victim logs in — session ID stays the same
4. Attacker uses the known session ID to access the victim's authenticated session

---

## 5. Command Injection

**Location:** auth1.php
**CWE:** CWE-78 | **OWASP:** A03:2021 - Injection

**Root cause:** User input from the `target` parameter was passed directly to `shell_exec()` without validation. `localhost && dir` would execute both `ping` and `dir`.

**Your fix (multi-layer):**
1. **Regex whitelist:** `preg_match('/^[a-zA-Z0-9.\-]+$/', $target)` — only allows alphanumeric, dots, hyphens. Blocks `&&`, `;`, `|`, backticks
2. **IP/hostname validation:** `filter_var($target, FILTER_VALIDATE_IP)` or hostname regex
3. **Shell escaping:** `escapeshellarg($target)` wraps input in quotes and escapes specials
4. **Output sanitisation:** `RemoveXSS($cmd)` prevents XSS if command output contains HTML

**Why it works:** Each layer blocks a different attack vector. Even if one layer is bypassed, the others catch it. The regex alone blocks all shell metacharacters.

**Tradeoffs:** Strict whitelist may reject some valid but unusual hostnames. This is acceptable — security over convenience for a ping utility.

**If asked "why not just escapeshellarg alone?":** Defence in depth. `escapeshellarg` has had bypass vulnerabilities in specific PHP versions. The regex whitelist ensures only safe characters reach the shell regardless.

---

## 6. Directory Traversal

**Location:** auth2.php
**CWE:** CWE-22 | **OWASP:** A01:2021 - Broken Access Control

**Root cause:** User input was passed directly to `file_get_contents()`. `../../../../windows/system32/calc.exe` could read files outside the web root.

**Your fix:**
1. **Whitelist:** `$allowedFiles = array('yellow.txt', 'Yellow.txt')` — only specific files allowed
2. **basename():** Strips all directory components, so `../../etc/passwd` becomes `passwd`
3. **realpath():** Resolves the canonical path (follows symlinks, resolves `.` and `..`)
4. **strpos():** Confirms the resolved path starts within the application directory

**Why it works:** Even if an attacker crafts a path that somehow passes basename, realpath + strpos ensures the final path is within the allowed directory. The whitelist is the strongest control — only `yellow.txt` is accessible regardless.

**Tradeoffs:** Very restrictive — only whitelisted files can be read. If new files need to be accessible, the whitelist must be updated manually. This is the safest approach for a known, small set of files.

---

## 7. Insufficient Session Management (Direct Page Access)

**Location:** admin.php, auth1.php, auth2.php, login.inc.php
**CWE:** CWE-285 | **OWASP:** A01:2021 - Broken Access Control

**Root cause:** admin.php had an empty `if` block for access control. auth1.php and auth2.php sent `header()` redirects without calling `exit()`, so PHP continued executing and the page content was still generated and sent.

**Your fix:**
- admin.php: Proper `if/else` with `header("Location: index.php")` followed by `exit()`
- auth1.php, auth2.php: Added `exit()` after redirect
- login.inc.php: Added `exit()` after the lockout redirect

**Why it works:** Without `exit()`, PHP sends the redirect header but continues executing the rest of the page. An attacker can simply ignore the redirect header (using curl, Burp Suite, etc.) and read the response body. `exit()` immediately stops PHP execution — no content is generated.

**Tradeoffs:** None. `exit()` after redirect is standard practice with zero downsides.

**If asked "can you demonstrate the issue without exit?":** Use browser dev tools or `curl -v` to see that the response body still contains page content even when a `Location` header is sent.

---

## 8. CSRF (Cross-Site Request Forgery)

**Location:** includes/reset.inc.php, change.php
**CWE:** CWE-352 | **OWASP:** A01:2021 - Broken Access Control

**Root cause:** The form generated a CSRF token but the server never validated it. Any request with any token (or no token) was accepted.

**Your fix:**
- **Token generation** in change.php: `bin2hex(random_bytes(32))` — cryptographically secure
- **Token validation** in reset.inc.php: `hash_equals($_SESSION['csrf'], $csrfToken)` — timing-safe comparison
- **Single-use:** Token is invalidated with `unset($_SESSION['csrf'])` after use
- **Password verification:** `password_verify($oldpass, $row['user_pwd'])` replaces `strcmp()`
- **Password hashing:** `password_hash($newpass, PASSWORD_BCRYPT)` before storage

**Why it works:** The token is unpredictable (random_bytes), so an attacker cannot forge it. hash_equals prevents timing attacks where the attacker measures response times to guess the token character by character. Single-use prevents replay attacks. password_verify correctly compares plaintext against bcrypt hashes (strcmp would never match). Hashing the new password ensures consistency with the registration flow.

**Tradeoffs:** Token must be included in every form. If the session expires, the token becomes invalid and the user must reload the form. This is acceptable for security.

**If asked "why was strcmp broken?":** strcmp compares two raw strings. The old password is plaintext (e.g., "AdminPass1!") and the stored password is a bcrypt hash (e.g., "$2y$10$..."). These will never be equal, so password changes would always fail.

**If asked "what's the CSRF attack scenario?":**
1. Victim is logged into the app
2. Attacker creates a malicious page with a hidden form/link pointing to `reset.inc.php` with attacker-chosen passwords
3. Victim visits the attacker's page — their browser sends the request with their session cookie
4. Without CSRF validation, the password gets changed to whatever the attacker chose

---

## 9. Insufficient Brute-Force Protection

**Location:** includes/signup.inc.php
**CWE:** CWE-307 | **OWASP:** A07:2021 - Identification and Authentication Failures

**Root cause:** Login had brute-force protection but registration did not. Unlimited registration attempts from the same IP with no throttling.

**Your fix:**
- Extended the existing `failedLogins` table mechanism to registration
- IP-based tracking with counter increment on each attempt
- Lockout after 5 attempts for 3 minutes
- Counter resets on successful registration

**Why it works:** Rate limiting slows automated attacks. The 3-minute lockout makes large-scale brute-force impractical while avoiding permanent lockout (which could be abused as DoS).

**Tradeoffs:** IP-based tracking is the only option before authentication (no trusted identity to track). Attackers using proxies/VPNs can rotate IPs to bypass it. Registration and login share the `failedLogins` table, so failures in one affect the other. A timed lockout (vs permanent) balances security with usability.

**If asked "why not CAPTCHA?":** CAPTCHA would be a stronger control but adds complexity and third-party dependencies. IP-based rate limiting is appropriate for extending the existing mechanism as the assignment required.

---

## 10. Page Caching

**Location:** header.php
**CWE:** CWE-525 | **OWASP:** A04:2021 - Insecure Design

**Root cause:** No cache-control headers were sent. Browsers cached authenticated pages by default. After logout, pressing Back showed cached content.

**Your fix:**
- HTTP headers in header.php: `no-cache, no-store, must-revalidate, max-age=0`, `Pragma: no-cache`, past `Expires` date
- JavaScript `pageshow` event listener to handle back-forward cache (bfcache): detects back/forward navigation using `event.persisted` and Performance Navigation API, forces a full reload

**Why it works:** The HTTP headers tell the browser never to cache or reuse the page. `no-store` prevents saving to disk, `must-revalidate` forces revalidation, `Pragma` covers HTTP/1.0 clients. The JavaScript listener catches modern browsers' bfcache, which can serve a visual snapshot bypassing HTTP headers entirely — forcing a reload ensures the server's session checks are always enforced.

**Tradeoffs:** Every page load hits the server (no caching benefit). For an authenticated security application, this is the correct tradeoff — performance vs security. The bfcache listener adds minimal JavaScript overhead.

**If asked "why both headers AND JavaScript?":** HTTP cache-control headers handle traditional caching. But modern browsers have bfcache, which stores a complete page snapshot in memory and restores it on back/forward navigation — this bypasses HTTP headers entirely. The JavaScript listener is needed to catch this case.

---

## General Tips for the Interview

1. **Name the vulnerability first**, then classify (CWE + OWASP), then explain
2. **Explain the root cause** before jumping to the fix
3. **Know the difference** between reflective vs persistent XSS, and be ready to explain it
4. **Be honest about tradeoffs** — it shows deeper understanding
5. **If you don't know something**, say "I'm not sure but here's what I think..." rather than guessing
6. **Be ready to demo** — Richard may ask you to show the vulnerability or the fix working
7. **Know where your code is** — be able to quickly find the relevant file and line
