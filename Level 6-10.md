
## Level 5 → Level 6

**Title:** Authentication Bypass via Cookie Manipulation

**Summary:**
After logging in, the page greets you with "Access disallowed. You are not logged in." — which is odd, because I just logged in. The server isn't tracking the session the right way. The application relies solely on a client-controlled cookie to determine authentication state. And since cookies are client-side, they can be changed.

---

### Steps to Reproduce
1. Log in at `http://natas5.natas.labs.overthewire.org`
2. The page says you're not logged in despite authenticating
3. Open **DevTools** (`F12`) → **Application** tab → **Cookies**
4. You'll see a cookie: `loggedin=0`
5. Double-click the value and change it to `1`, then refresh the page
6. Access is granted — the password for natas6 is displayed

---

### Impact
If login state is tracked using a simple, unverified cookie value, any user can flip the flag and gain access. In a real application, this could mean bypassing a paywall, accessing admin functionality, or impersonating another user — all without knowing their password.

---

### Mitigation
Session state must never be trusted from the client. The server should maintain session records (via a session ID tied to server-side state), and the session ID itself should be unpredictable and cryptographically random. A boolean cookie like `loggedin=0/1` is not a session mechanism — it's a suggestion the server is blindly accepting.

---

### Takeaways
- Cookies are stored on the client and can be freely edited. Never use them to store trust decisions.
- Always inspect cookies early in recon — they often reveal how the application manages state.
- Proper session management is one of the most fundamental things to get right in web security.

---
---

## Level 6 → Level 7

**Title:** Source Code Disclosure Leading to Secret Extraction

**Summary:**
This level presents a form asking for a "secret" — entered the right one and I get the password. The page also provides a link to view the PHP source code, which is where things get interesting. The secret isn't hardcoded in the main file, but the source reveals exactly where it's being pulled from.

---

### Steps to Reproduce
1. Log in at `http://natas6.natas.labs.overthewire.org`
2. Click **View sourcecode** — the PHP source is shown
3. Notice this line near the top:
   ```php
   include "includes/secret.inc";
   ```
4. Navigate directly to that file:
   ```
   http://natas6.natas.labs.overthewire.org/includes/secret.inc
   ```
5. The file contains the plaintext secret — something like `<string>`
6. Submit it in the form to receive the password for natas7

---

### Impact
Including sensitive files (like config files or secret stores) within the web root means they can potentially be accessed directly if the server isn't configured to block them. In this case, `.inc` files aren't treated as PHP by the server — they're served as plain text, exposing their contents to anyone who knows (or guesses) the path.

---

### Mitigation
Files containing secrets should never live inside the web root. Place them above the document root so they're accessible to the application server but not directly via HTTP. Also, ensure the web server is configured to deny direct access to config and include files. For `.inc` files specifically, they should either be stored outside the web root or the server should be configured to parse them as PHP (so they execute rather than render).

---

### Takeaways
- Source code disclosure often reveals more than intended — pay close attention to `include` and `require` statements.
- Just because a file isn't linked doesn't mean it isn't accessible. Guessing or deriving include paths is a real technique.
- Sensitive files inside the web root are one misconfiguration away from being public.

---
---

## Level 7 → Level 8

**Title:** Local File Inclusion (LFI) via Unsanitized URL Parameter

**Summary:**
The page has two links — "Home" and "About" — and clicking them changes the URL to something like `index.php?page=home` and `index.php?page=about`. That `page` parameter is being passed directly to a PHP file inclusion function without any sanitization. This means it can point at any file on the server's filesystem, not just the ones the developer intended.

---

### Steps to Reproduce
1. Log in at `http://natas7.natas.labs.overthewire.org`
2. Click "Home" or "About" — notice the URL changes to `?page=home` or `?page=about`
3. Also check the page source — there's a helpful HTML comment:
   ```html
   <!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
   ```
4. Replace the `page` parameter with the absolute path to the password file:
   ```
   http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8
   ```
5. The password is printed directly on the page

---

### Impact
Local File Inclusion is a serious vulnerability. In addition to reading sensitive system files (like `/etc/passwd` or application credentials), LFI can sometimes be escalated to Remote Code Execution by including server log files that contain injected PHP code. At minimum, it gives an attacker arbitrary read access to the server's filesystem — limited only by the web server user's permissions.

---

### Mitigation
User-supplied input should never be passed directly into file inclusion functions like `include()`, `require()`, or `file_get_contents()`. A whitelist approach works best — define the pages the application knows about and only serve those. Input should be validated against that list; anything not on it gets rejected. Absolute path traversal should also be blocked by stripping or rejecting `/` characters in the parameter.

---

### Takeaways
- If a URL parameter appears to control what content is loaded, always test it for LFI.
- HTML comments left in production code can hand attackers exactly the information they need.
- LFI is one of the more impactful vulnerability classes — it's worth understanding well.

---
---

## Level 8 → Level 9

**Title:** Reverse Engineering an Encoding Scheme to Recover a Secret

**Summary:**
Same setup as Level 6 — a form asking for a secret. The source code is available again, but this time the secret isn't stored in a separate file. Instead, it's been encoded and hardcoded directly into the PHP. The encoding function is also right there in the source. The challenge is to reverse it and work backwards to the original secret.

---

### Steps to Reproduce
1. Log in at `http://natas8.natas.labs.overthewire.org`
2. Click **View sourcecode** — you'll find the following PHP:
   ```php
   $encodedSecret = "3d3d516343746d4d6d6c315669563362";

   function encodeSecret($secret) {
       return bin2hex(strrev(base64_encode($secret)));
   }
   ```
3. The encoding pipeline is: `base64_encode` → `strrev` → `bin2hex`
4. To reverse it, apply the inverse in the opposite order: `hex2bin` → `strrev` → `base64_decode`
5. Run this in PHP (or use CyberChef):
   ```php
   echo base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362")));
   ```
6. This gives the plaintext secret — submit it in the form to get the password for natas9

Using CyberChef:
- Input: `3d3d516343746d4d6d6c315669563362`
- Operations (in order): `From Hex` → `Reverse` → `From Base64`

---

### Impact
Encoding is not encryption. Base64, hex, and string reversal are all trivially reversible — they add zero security. Developers sometimes confuse obfuscation with protection, hardcoding "encoded" secrets into source code and thinking it's safe. Once the source is exposed (or the application is decompiled), the secret is recoverable in seconds.

---

### Mitigation
Secrets must be encrypted, not just encoded. If a secret needs to be compared against user input, use a proper hashing scheme with a salt (like bcrypt or Argon2) — not a reversible encoding. Hardcoded secrets in source code are also a risk in themselves; they should live in environment variables or a secrets manager, not in the codebase.

---

### Takeaways
- Encoding ≠ encryption. `base64` and `hex` are representations, not protection.
- When source code is available, look for encoding functions — reversing them is usually straightforward.
- CyberChef is an excellent tool for experimenting with encoding and decoding chains.

---
---

## Level 9 → Level 10

**Title:** OS Command Injection via Unsanitized Input in PHP `passthru()`

**Summary:**
Level 9 presents a word search form. Type something in, and the server searches a dictionary file for matching words. Sounds harmless. But viewing the source reveals that your input is being passed directly into a shell command with no sanitization whatsoever — which means you can inject your own commands and have the server execute them.

---

### Steps to Reproduce
1. Log in at `http://natas9.natas.labs.overthewire.org`
2. Click **View sourcecode** — the relevant PHP is:
   ```php
   $key = $_REQUEST["needle"];
   passthru("grep -i $key dictionary.txt");
   ```
3. The input is dropped straight into the shell command. Using `;` lets you terminate the `grep` and run a second command
4. In the search box, enter:
   ```
   ; cat /etc/natas_webpass/natas10 ;
   ```
5. The full command that runs on the server becomes:
   ```bash
   grep -i ; cat /etc/natas_webpass/natas10 ; dictionary.txt
   ```
6. The `grep` fails silently, `cat` runs and prints the password, and the trailing `;` cleans up the rest

---

### Impact
Command injection is one of the most severe web vulnerabilities. With shell access, an attacker can read arbitrary files, exfiltrate data, create backdoors, pivot to other systems, or take the server completely offline. It consistently appears in the OWASP Top 10 and is a critical finding in any real pentest.

---

### Mitigation
User input should never be passed directly to shell functions like `passthru()`, `exec()`, `system()`, or `shell_exec()`. If shell commands are genuinely necessary, use `escapeshellarg()` to sanitize input before it touches the command line. Better yet, rethink the approach entirely — in most cases, the same result can be achieved with safer language-level functions that don't invoke a shell at all.

---

### Takeaways
- If user input touches a shell command, assume command injection is possible until proven otherwise.
- `;`, `&&`, `||`, and `|` are all shell control characters — any of them can be used to chain commands.
- `passthru()` without sanitization is essentially handing a terminal to your users.

---
