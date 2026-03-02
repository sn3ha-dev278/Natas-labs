
---

> These writeups document my hands-on learning through the Natas wargame series. Each level taught me something concrete about how web vulnerabilities work in practice — not just in theory.

---

## Level 0 → Level 1

**Title:** Information Disclosure via HTML Source Code

**Summary:**
The very first level sets the tone for the entire series — not everything meant to be hidden actually is. The password was sitting in the page's HTML source, tucked inside a comment. No tools, no exploits. Just the habit of looking where most users don't.

---

### Steps to Reproduce
1. Log in at `http://natas0.natas.labs.overthewire.org` using `natas0:natas0`
2. The page says the password is "on this page" — but nothing is visible
3. Right-click → **View Page Source** (or press `Ctrl+U`)
4. Look for an HTML comment in the source:
   ```html
   <!--The password for natas1 is <password> -->
   ```
5. Use this password to log into Level 1

---

### Impact
Low complexity, high consequence. Credentials in client-side HTML are exposed to anyone who opens the source — no special skills or tools needed. In a real application, this could mean exposed API keys, internal paths, or admin credentials sitting in plain sight.

---

### Mitigation
Sensitive data should never touch the client side. Credentials and secrets belong in server-side environment variables or a secrets manager. HTML comments are stripped in build pipelines for exactly this reason.

---

### Takeaways
- "View Source" is one of the first habits to build as a web security learner and should be instinctive.
- Anything the browser receives, the user can read — rendered or not.
- Information disclosure doesn't need a fancy exploit. Sometimes a right-click is enough.

---
---

## Level 1 → Level 2

**Title:** Bypassing Client-Side Restrictions (Disabled Right-Click)

**Summary:**
This level adds a JavaScript-based right-click blocker to the mix — presumably to stop users from viewing the source the same way as before. The password is still in a comment, but the intended path to get there is blocked. Except, of course, it isn't really blocked at all.

---

### Steps to Reproduce
1. Log in at `http://natas1.natas.labs.overthewire.org`
2. Right-clicking triggers a JavaScript alert — context menu is blocked
3. Bypass the restriction using any of the following:
   - Press `Ctrl+U` to open page source directly
   - Type `view-source:http://natas1.natas.labs.overthewire.org` in the address bar
   - Press `F12` to open browser DevTools — JavaScript cannot block this
4. Find the password in an HTML comment

---

### Impact
Any protection enforced purely in JavaScript can be bypassed by the end user. Sites that rely on disabled right-click to "protect" images, text, or source code give themselves a false sense of security. A malicious user would get through in seconds.

---

### Mitigation
Client-side JavaScript is never a security boundary. If something needs to be protected, that protection must live on the server. Right-click blocking is acceptable as a UX preference but not as a security control.

---

### Takeaways
- The browser always has the full source. JavaScript can only change what's *displayed*, not what's *there*.
- `Ctrl+U`, `view-source:`, and DevTools (`F12`) are good to have in muscle memory.
- Client-side ≠ secure. This is a theme that shows up again and again in web security.

---
---

## Level 2 → Level 3

**Title:** Sensitive File Exposure via Directory Listing

**Summary:**
The page says "there is nothing on this page" — and for once, the HTML source confirms it. No comment, no obvious clue. But a single image tag in the source pointed to a `files/` directory, and that directory turned out to be wide open for browsing.

---

### Steps to Reproduce
1. Log in at `http://natas2.natas.labs.overthewire.org`
2. View page source — nothing sensitive in the HTML, but notice:
   ```html
   <img src="files/pixel.png">
   ```
3. Navigate directly to the directory:
   ```
   http://natas2.natas.labs.overthewire.org/files/
   ```
4. The server returns a directory listing — find `users.txt` in the list
5. Open `users.txt` to find the password for natas3

---

### Impact
Directory listing misconfigurations are a common findings. Exposed directories can reveal backup files, config files, database exports, internal documentation, and more. The damage depends on what's in the directory.

---

### Mitigation
Directory listing should be explicitly disabled in the web server configuration. In Apache, remove the `Indexes` option. In Nginx, ensure `autoindex` is set to `off`. Beyond that, sensitive files like `users.txt` should never be in a web-accessible location, regardless of listing settings.

---

### Takeaways
- When you see a file path in source code, always check if the parent directory is browseable.
- Default server configurations are often permissive. Locking things down requires deliberate effort.
- "Nothing on this page" only meant nothing in the *page* — the server had plenty more to offer.

---
---

## Level 3 → Level 4

**Title:** Sensitive Path Disclosure via robots.txt

**Summary:**
The hint this time was that "not even Google will find it." That's a direct reference to `robots.txt` — the file used to tell search engine crawlers which parts of a site to skip. The problem is that `robots.txt` is publicly accessible, and listing a path as disallowed is essentially publishing a map to whatever you're trying to hide.

---

### Steps to Reproduce
1. Log in at `http://natas3.natas.labs.overthewire.org`
2. Navigate to:
   ```
   http://natas3.natas.labs.overthewire.org/robots.txt
   ```
3. The file contains:
   ```
   Disallow: /s3cr3t/
   ```
4. Visit that path directly:
   ```
   http://natas3.natas.labs.overthewire.org/s3cr3t/
   ```
5. Directory listing is enabled — open `users.txt` to find the password for natas4

---

### Impact
`robots.txt` is one of the first files checked during the reconnaissance phase of a pentest. Real-world cases have seen admin panels, staging environments, backup directories, and internal tools inadvertently exposed this way. The file meant to hide something ended up advertising its location.

---

### Mitigation
`robots.txt` should not reference sensitive or restricted paths. If a resource needs to be inaccessible, it must be protected with proper authentication and authorization — not just omitted from crawlers. A disallowed path with no access control is a labeled door with no lock.

---

### Takeaways
- `robots.txt` is a recon goldmine. Check it early, every time.
- Security through obscurity is not security — it just shifts the problem.
- "Don't look here" is never an access control mechanism.

---
---

## Level 4 → Level 5

**Title:** Access Control Bypass via HTTP Referer Header Spoofing

**Summary:**
This level introduces HTTP headers as an access control mechanism — and why that's a bad idea. The server grants access only to requests that appear to come from `natas5.natas.labs.overthewire.org`, checked using the `Referer` header. Since the client controls that header, the "restriction" is trivially bypassable.

---

### Steps to Reproduce
1. Log in at `http://natas4.natas.labs.overthewire.org`
2. The page says access is denied — you're coming from the wrong URL
3. Open **Burp Suite**, enable the proxy, and intercept the request to natas4
4. In the intercepted request, add or modify the Referer header:
   ```
   Referer: http://natas5.natas.labs.overthewire.org/
   ```
5. Forward the modified request — the server accepts it and returns the password

---

### Impact
Any application using the `Referer` header (or similar client-supplied headers like `X-Forwarded-For`) for authorization decisions is vulnerable to this bypass. In real environments, this pattern has been used to restrict admin panels, internal APIs, and gated features — all of which can be bypassed by anyone who knows to look at the headers.

---

### Mitigation
Access control must be enforced server-side using proper authentication — session tokens, signed cookies, or API keys. HTTP headers provided by the client should be treated as untrusted input.

---

### Takeaways
- HTTP headers are client-controlled. They can be set to anything. Never use them for authorization.
- Burp Suite's interceptor is one of the most useful tools for understanding how HTTP requests work.
- Real access control requires verifiable server-side state — not a header value.

---
