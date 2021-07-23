# Notes on Stanford CS 253 Web Security

<div style="float:left">

<div>
<span style="position: absolute;"><img style="border-radius: 50%;" alt="Adarsh Chandran" src="https://miro.medium.com/fit/c/56/56/0*bTi72TPF4cc2iB4y.jpg" width="28" height="28"></span>
<span style="color:#1a8917; margin-left:40px;font-size: 13px;">Adarsh Chandran</span>
<span style="color:#757575;font-size:13px;margin-left:5px">Apr 15, 2020  · 13 min read</span>
</div>

<br/><br/>

<img alt="" class="w hl hm" src="https://miro.medium.com/max/1400/1*A7JNw02M8p7FVotoI-ypxA.png" width="700" height="390" role="presentation">

</p>

These are notes that I’ve prepared after attending the lecture Stanford CS 253 by <span style="font-size:15px;"><a href="https://medium.com/u/1299c645ef11?source=post_page-----54696c377ad4--------------------------------" target="_blank" rel="noopener">Feross Aboukhadijeh</a></span>. His lecture is very interesting and he is a fast coder. You can follow him on twitter as well.

</p>

### Web Security

</p>

<img alt="" class="nn to fe en ej jq w c" width="700" height="396" role="presentation" src="https://miro.medium.com/max/1400/1*-u6HANUvCTraHn_DCSDf0w.png" srcset="https://miro.medium.com/max/552/1*-u6HANUvCTraHn_DCSDf0w.png 276w, https://miro.medium.com/max/1104/1*-u6HANUvCTraHn_DCSDf0w.png 552w, https://miro.medium.com/max/1280/1*-u6HANUvCTraHn_DCSDf0w.png 640w, https://miro.medium.com/max/1400/1*-u6HANUvCTraHn_DCSDf0w.png 700w" sizes="700px">

</p>

The motive behind attacking a computer system in 2020 includes mining Cryptocurrencies, Ransomware, and Political motivation. There comes the importance of Same Origin Policy where sites are isolated from each other while running in the same browser. We need Server app security when attackers can send anything to the server and Client app security to prevent the user from being attacked while using web apps locally. Web security is hard due to several reasons like different sites interacting in the same tab (“mashups”), desire for high performance, etc. The browser can’t keep you safe when malicious sites can download from anywhere, spawn processes, Save/read data from the filesystem, etc

</p>

### DNS and HTTP

</p>

> ***`Root name servers`*** are the servers at the root of the Domain Name System (DNS) hierarchy.

</p>

When you type a stanford.edu and press enter, the client asks DNS Recursive Resolver to lookup stanford.edu to Root name-server, then to look “.edu” name-server and then to “standford.edu” name-server to return the IP address and then send the HTTP request to the server. Once the DNS lookup is complete, a TCP socket is opened to send an HTTP request and read the response. HTML response will be parsed to the DOM and the page will be rendered based on the DOM.

</p>
<img alt="" class="nn to fe en ej jq w c" width="700" height="400" role="presentation" src="https://miro.medium.com/max/1400/1*38duiqndjYwjkYxLFl_hoA.png" srcset="https://miro.medium.com/max/552/1*38duiqndjYwjkYxLFl_hoA.png 276w, https://miro.medium.com/max/1104/1*38duiqndjYwjkYxLFl_hoA.png 552w, https://miro.medium.com/max/1280/1*38duiqndjYwjkYxLFl_hoA.png 640w, https://miro.medium.com/max/1400/1*38duiqndjYwjkYxLFl_hoA.png 700w" sizes="700px">
</p>
DNS hijacking can be done when an attacker change DNS records and direct visitors to an attacker web server. Different hijacking vectors include a malware changing user’s local DNS setting, hacked router or a hacked recursive DNS resolver. Privacy issues for DNS include plain-text queries, ISP selling user data, etc. Keeping an HTTP proxy server, which is a server between client and server, is good security practice.

</p>

### Cookie and Session Attacks

</p>

Cookies are used by the server to implement sessions. The server keeps a set of data related to a user’s current “browsing session”. This could be for keeping a user logged-in, shopping carts, user tracking, etc.

Ambient Authority is an access control based on a global and persistent property of a requester. The alternative is explicit authorization valid only for a specific action. Asking the user to log in when every time a user clicks on like button on Facebook is not a good idea.

</p>

>Do not use the cookie path for security. Use path only for performance optimization. Path attributes can be bypassed using an ***iframe*** with the path of cookie. *`iframe.contentDocument.cookie`* can fetch the cookie
</p>

<img alt="" class="nn to fe en ej jq w c" width="700" height="94" role="presentation" src="https://miro.medium.com/max/1400/1*iJ_xOBFt2ISkVq6o1uf1lg.png" srcset="https://miro.medium.com/max/552/1*iJ_xOBFt2ISkVq6o1uf1lg.png 276w, https://miro.medium.com/max/1104/1*iJ_xOBFt2ISkVq6o1uf1lg.png 552w, https://miro.medium.com/max/1280/1*iJ_xOBFt2ISkVq6o1uf1lg.png 640w, https://miro.medium.com/max/1400/1*iJ_xOBFt2ISkVq6o1uf1lg.png 700w" sizes="700px">

</p>

**`Secure`** — cookie attribute to prevent the cookie from being sent over unencrypted HTTP connections

**`HttpOnly`** — cookie attribute to prevent the cookie from being read from JavaScript

**`SameSite`** — cookie attribute to prevent the cookie from being sent with requests initiated by other sites and prevent Cross-Site Request Forgery (CSRF).

**`SameSite=None`** — default, always send cookies

**`SameSite=Lax`** — withhold cookies on subresource requests originating from other sites, allow them on top-level requests

**`SameSite=Strict`** — only send cookies if the request originates from the website that set the cookie

>Use a reasonable expiration date for your cookies preferably 30–90 days

</p>

### Same Origin Policy

The fundamental security model of the web is — **`Two pages from different sources should not be allowed to interfere with each other.`**

Given two separate JavaScript execution contexts, one should be able to access the other only if the protocols, hostnames, and port numbers associated with their host documents match exactly. This “protocol-host-port tuple” is called an “origin”.

<img alt="" class="nn to fe en ej jq w c" width="700" height="396" role="presentation" src="https://miro.medium.com/max/1400/1*3PoxX-fc00z6P7hNZeQ60g.png" srcset="https://miro.medium.com/max/552/1*3PoxX-fc00z6P7hNZeQ60g.png 276w, https://miro.medium.com/max/1104/1*3PoxX-fc00z6P7hNZeQ60g.png 552w, https://miro.medium.com/max/1280/1*3PoxX-fc00z6P7hNZeQ60g.png 640w, https://miro.medium.com/max/1400/1*3PoxX-fc00z6P7hNZeQ60g.png 700w" sizes="700px">
</p>

There are Same Origin Policy exceptions to allow two different origins to communicate. **`document.domain(a bad idea!), fragment identifier communication, and the postMessage API`**. The PostMessage API is secure cross-origin communication between cooperating origins. Always specify the intended recipient or expected sender in postMessage to avoid an attack. Embedded static resources like images, scripts, and styles can come from another origin.

Since Ambient Authority is implemented by cookies, attacker.com can embed the user’s real avatar from the target site.

>**`SameSite`** cookie attribute is a solution.

HTTP Referer header is another solution where we can reject any requests from origins that are not in our “allowlist”. However, caches can be a villain if the attacker is accessing a cached page since the server will not get the chance to check the Referer header. So add a **`Vary: Referer`** header or **`Cache-Control: no-store`** header. Still, sites can opt-out of sending the Referer header which defeats this whole mechanism. So, **`just use SameSite cookies!`**

### Exceptions to the Same Origin Policy and Cross-Site Script Inclusion

<img alt="" class="nn to fe en ej jq w c" width="700" height="390" role="presentation" src="https://miro.medium.com/max/1400/1*yYmVnS_sufbAAPeZOr1_Cg.png" srcset="https://miro.medium.com/max/552/1*yYmVnS_sufbAAPeZOr1_Cg.png 276w, https://miro.medium.com/max/1104/1*yYmVnS_sufbAAPeZOr1_Cg.png 552w, https://miro.medium.com/max/1280/1*yYmVnS_sufbAAPeZOr1_Cg.png 640w, https://miro.medium.com/max/1400/1*yYmVnS_sufbAAPeZOr1_Cg.png 700w" sizes="700px">

</p>

We need to disallow a site from embedding our sites to prevent clickjacking attacks. **`Clickjacking`** attacks trick web users into performing an action that they did not intend, typically by rendering an invisible page element on top of the action that the user thinks they are performing. This creates a very bad experience for the user.

</p>

**`X-Frame-Options`** HTTP header has options to not to display the page in an iframe or display in an iframe on the same origin as the page itself.

To prevent CSRF, embedding images from our site or embedding scripts from our site, check Referer header and Origin header with an “allowlist”(not foolproof), **`SameSite cookies and using unpredictable URL are good choices.`**

**`Cross-Origin Resource Sharing (CORS)`** is a mechanism that uses additional HTTP headers to tell browsers to give a web application running at one origin, access to selected resources from a different origin. Never set **`Access-Control-Allow-Origin`** header(no fetch read) or never return JSONP format to ensure private data returned by an authenticated API route isn’t read by other sites.

**`Cross-Site Script Inclusion (XSSI)`** is a vulnerability when a resource is included using the script tag, the Same Origin Policy doesn’t apply because scripts have to be able to be included cross-domain. An attacker can thus read everything that was included using the script tag.

Google put **`)]}’`** at the beginning of all their API responses to prevent XSSI so that if the returned data would somehow have parsed as valid JavaScript, then it will guarantee it is a syntax error

### Cross-Site Scripting (XSS)

<img alt="" class="nn to fe en ej jq w c" width="700" height="386" role="presentation" src="https://miro.medium.com/max/1400/1*gPxUpP4CzoQEYdRHxmTxng.png" srcset="https://miro.medium.com/max/552/1*gPxUpP4CzoQEYdRHxmTxng.png 276w, https://miro.medium.com/max/1104/1*gPxUpP4CzoQEYdRHxmTxng.png 552w, https://miro.medium.com/max/1280/1*gPxUpP4CzoQEYdRHxmTxng.png 640w, https://miro.medium.com/max/1400/1*gPxUpP4CzoQEYdRHxmTxng.png 700w" sizes="700px">
</p>

**`Cross-site Scripting (XSS)`** is a “code injection” vulnerability when untrusted user data unexpectedly becomes code. In cross-site scripting (XSS), the unexpected code is JavaScript in an HTML document. In SQL injection, the unexpected code is extra SQL commands included a SQL query string. Once XSS is a success, the attacker can view the cookies and send any HTTP request with the user’s cookies. **`There are three main types of XSS attacks.`**

**`Reflected XSS`** — where the malicious script comes from the current HTTP request.
**`Stored XSS`** — where the malicious script comes from the website’s database.
**`DOM-based XSS`** — where the vulnerability exists in client-side code rather than server-side code.

### Cross-Site Scripting (XSS) Defenses

Code injection is caused when untrusted user data unexpectedly becomes code. **`A better name for Cross-Site Scripting would be “HTML Injection”`**. We need to “escape” or “sanitize” user input before combining it with code (the HTML template). Always “escape” the data on the way out of the database at render time. Also, use the frontend framework’s built-in HTML escaping functionality to “escape” user input.

>Use HttpOnly cookie attribute to prevent cookie from being read from JavaScript in the user’s browser

**`XSS`** is very common. So provide redundancy when security controls fail, or a vulnerability is exploited since, with the XSS, attacker code is running on the same page as the user’s data (cookies, other private data). Defense-in-depth can be employed by setting a strong password with two-factor authentication. Plus: email notifications which act as an audit log.

<img alt="" class="nn to fe en ej jq w c" width="700" height="396" role="presentation" src="https://miro.medium.com/max/1400/1*_B6m2Ptv9_HLjZsxs5QR4Q.png" srcset="https://miro.medium.com/max/552/1*_B6m2Ptv9_HLjZsxs5QR4Q.png 276w, https://miro.medium.com/max/1104/1*_B6m2Ptv9_HLjZsxs5QR4Q.png 552w, https://miro.medium.com/max/1280/1*_B6m2Ptv9_HLjZsxs5QR4Q.png 640w, https://miro.medium.com/max/1400/1*_B6m2Ptv9_HLjZsxs5QR4Q.png 700w" sizes="700px">

</p>

**`Content Security Policy (CSP)`** prevent our site from making requests to other sites. **`CSP`** is an added layer of security against **`XSS`**. Even if attacker code is running in the user’s browser in our site’s context, we can limit the damage they can do. Add the **`Content-Security-Policy`** header to an HTTP response. **`CSP`** blocks HTTP requests which would violate the policy. The **`‘strict-dynamic’`** source expression allows script loaded via nonce- or hash-based whitelists to load other scripts.

**`CSP`** only protects against **`Reflected XSS`** and **`Stored XSS`**. For **`DOM-based XSS`**, a new web spec called **`“Trusted Types”`** that if deployed in browsers would completely eliminate most **`DOM-based XSS`**

### Fingerprinting and Privacy on the Web

<img alt="" class="nn to fe en ej jq w c" width="700" height="530" role="presentation" src="https://miro.medium.com/max/1400/1*grtCg8_ZWsjO_528IxqB6Q.png" srcset="https://miro.medium.com/max/552/1*grtCg8_ZWsjO_528IxqB6Q.png 276w, https://miro.medium.com/max/1104/1*grtCg8_ZWsjO_528IxqB6Q.png 552w, https://miro.medium.com/max/1280/1*grtCg8_ZWsjO_528IxqB6Q.png 640w, https://miro.medium.com/max/1400/1*grtCg8_ZWsjO_528IxqB6Q.png 700w" sizes="700px">

</p>

Birth of tracking can be due to terrible HTTP auth and the need for authentication. Asking the user to login every time is not a feasible model.

**`Classic tracking`** — the server gives a token to the user. The user returns it on requests aka cookies. The token is what allows the re-identification

**`Fingerprinting / passive tracking`** — Website finds things different about each visitor using many identifies including browser size, extra fonts, audio/video hardware, installed plugins, etc.

Fingerprinting counter-measures include Removing the functionality, Make the functionality consistent, Restrict access, Noise(make the same thing different every time) and “privacy budget”.

### Denial-of-service, Phishing, Side Channels

>Fun activity: go to TheAnnoyingSite.com and hold down the space bar for 3 seconds

**`UI Denial-of-service`** attack is done to trap the user on a site by overriding browser defaults. This is done for harmless fun to create scareware.

The browser needs a way to break out of infinite loops without quitting the browser. Initially, the browsers added a checkbox on alert modal to stop further alerts but modern-day browsers are multiprocess now, so if a tab wants to go into an infinite loop that doesn’t prevent the tab’s close button from working. Just let the site infinitely loop as long as the user can close the misbehaving tab

>Add rel=’noopener’ to all links with target=’_blank’ to prevent Tabnabbing attack. The opened site’s window.opener will be null

**`Phishing`** — Tricking the user to tell you their password or other sensitive information by acting like a reputable entity. It is often easier than attacking security if a system directly

<img alt="" class="nn to fe en ej jq w c" width="700" height="398" role="presentation" src="https://miro.medium.com/max/1400/1*MzYuQ5LDeXM5H5YBx7AFJw.png" srcset="https://miro.medium.com/max/552/1*MzYuQ5LDeXM5H5YBx7AFJw.png 276w, https://miro.medium.com/max/1104/1*MzYuQ5LDeXM5H5YBx7AFJw.png 552w, https://miro.medium.com/max/1280/1*MzYuQ5LDeXM5H5YBx7AFJw.png 640w, https://miro.medium.com/max/1400/1*MzYuQ5LDeXM5H5YBx7AFJw.png 700w" sizes="700px">

</p>

**`Side-channel attacks`** — An attack based on information gained from the implementation of a computer system, rather than weaknesses in the implemented algorithm itself. Possible sources of leaks: Timing information, power consumption, electromagnetic leaks, sound can provide an extra source of information, which can be exploited.

There is a tension between the security and capabilities of the web browser. Phishing is a human problem, even though technical solutions can help. Side channels exist all over the place and are really hard to prevent

### Code Injection

User-supplied data is received, manipulated and acted upon so that what the interpreter processes are a mix of the instructions written by the programmer and the data supplied by the user. 

>Code injection was already mentioned in Cross-site scripting (XSS).

<img alt="" class="nn to fe en ej jq w c" width="700" height="223" role="presentation" src="https://miro.medium.com/max/1400/1*v7AWpPmfBwvkstgasuF5Rw.png" srcset="https://miro.medium.com/max/552/1*v7AWpPmfBwvkstgasuF5Rw.png 276w, https://miro.medium.com/max/1104/1*v7AWpPmfBwvkstgasuF5Rw.png 552w, https://miro.medium.com/max/1280/1*v7AWpPmfBwvkstgasuF5Rw.png 640w, https://miro.medium.com/max/1400/1*v7AWpPmfBwvkstgasuF5Rw.png 700w" sizes="700px">

</p>

**`SQL Injection`** is another code injection strategy where the aim is to read or modify database data. Never build SQL queries with string concatenation. Instead, go for parameterized SQL or ORMs. SQL injection attacks are possible when the application combines unsafe user-supplied data with SQL query strings.

>Easy SQL injection solution: Use parameterized SQL to sanitize the user input automatically; do not attempt to do it yourself

### Transport Layer Security (TLS)

The problem is with **`HTTP`** because it is not secure. Network attackers can control network infrastructures like routers or DNS servers. Secure communications require **`privacy`**(No eavesdropping), **`integrity`**(No tampering) and **`Authentication`**(No impersonation).

**`Hypertext Transfer Protocol Secure (HTTPS)`** keeps browsing safe by securely connecting the browser with the website server. HTTPS relies on Transport Layer Security (TLS) encryption to secure connections.

>When TLS is used with HTTP, we call it HTTPS

**`Anonymous Diffie-Hellman key exchange`** — Keeping communication between client and server using a key exchange and thus giving **`privacy`**(secure against eavesdropping). However, it lacks **`authentication`** since the client doesn’t know with which server it performed key exchange and It’s possible that the client securely derived a key with the network attacker instead of the intended server!

<img alt="" class="nn to fe en ej jq w c" width="700" height="398" role="presentation" src="https://miro.medium.com/max/1400/1*hPsbZXqr9Sy6QYasbNpXrg.png" srcset="https://miro.medium.com/max/552/1*hPsbZXqr9Sy6QYasbNpXrg.png 276w, https://miro.medium.com/max/1104/1*hPsbZXqr9Sy6QYasbNpXrg.png 552w, https://miro.medium.com/max/1280/1*hPsbZXqr9Sy6QYasbNpXrg.png 640w, https://miro.medium.com/max/1400/1*hPsbZXqr9Sy6QYasbNpXrg.png 700w" sizes="700px">

</p>

If the client could authenticate the server it is performing key exchange with, then it could securely derive a shared key with that (and only that) server. Like the signed cookies, a similar signature approach **`Triple of algorithms (G, S, V)`** can be used.

**How does the client get the server’s public key?**

**`Certificate authorities (CAs)`** — is an entity that issues digital certificates. A certificate certifies that a named subject is the owner of a specific public key. There are around 60 Top-level CAs and around 1200 intermediate CAs. If any single CA is compromised, the security of all websites on the internet could be compromised

**`TLS Strip attack`** — an attacker intervenes in the redirection of the HTTP to the secure HTTPS protocol and intercepts a request from the user to the server. The attacker will then continue to establish an HTTPS connection between himself and the server, and an unsecured HTTP connection with the user, acting as a “bridge” between them.

**`HTTP strict transport security (HSTS)`** — To defend against the TLS Strip attack, the server tells the browser “no matter what protocol the user specifies, always use HTTPS”.

>Use HTTP header Strict-Transport-Security: max-age=31536000 to force the browser to use HTTPS for one year!

**`Downside`**: “Trust on first use model” means that first visit to a site is still not secure against man-in-the-middle!

**`HSTS Preload list`** — Browsers offer to hardcode sites that want to always be HTTPS only. **`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.`**

>Must send includeSubDomains and preload options.

Difficult/impossible to remove a domain once hardcoded into the browser itself

### Authentication

>Build systems that are secure even when the attacker has the user’s password

<img alt="" class="nn to fe en ej jq w c" width="700" height="381" role="presentation" src="https://miro.medium.com/max/1400/1*gRascgVb73d-jN-PJ6Uw8Q.png" srcset="https://miro.medium.com/max/552/1*gRascgVb73d-jN-PJ6Uw8Q.png 276w, https://miro.medium.com/max/1104/1*gRascgVb73d-jN-PJ6Uw8Q.png 552w, https://miro.medium.com/max/1280/1*gRascgVb73d-jN-PJ6Uw8Q.png 640w, https://miro.medium.com/max/1400/1*gRascgVb73d-jN-PJ6Uw8Q.png 700w" sizes="700px">
</p>

**`Authentication`** — Verify the user is who they say they are. Login form, Ambient authority(eg: HTTP cookies), HTTP authentication.

**`Authorization`** — Decide if a user has permission to access a resource. Access control lists(ACLs), Capability URLs.

**Network-based guessing attacks.**

* **`Brute force`**: Testing multiple passwords from a dictionary or other source against a single account

* **`Credential stuffing`**: Testing username/password pairs obtained from the breach of another site

* **`Password spraying`**: Testing a single weak password against a large number of different accounts

**Network-based guessing defenses**

* Limit the rate at which an attacker can make authentication attempts, or delay incorrect attempts

* Keep track of IP addresses and limit the number of unsuccessful attempts

* Temporarily ban the user after too many unsuccessful attempts

**CAPTCHA** — Completely Automated Public Turing test to tell Computers and Humans Apart. Difficult for visually impaired users. It takes the average person approximately 10 seconds to solve a typical CAPTCHA. Attackers can proxy CAPTCHA requests to another user in real-time. Dark market services offer cheap CAPTCHA solving services powered by humans.

>Never, ever, ever store passwords in plain text.

In a data breach, the attacker will learn all users’ passwords and be able to attack their accounts on other sites, assuming the user has re-used their password across sites (very likely). Has the plaintext password, then store the hash in the database.

<img alt="" class="nn to fe en ej jq w c" width="700" height="401" role="presentation" src="https://miro.medium.com/max/1400/1*ZcfEGwvoHT5QXtVW1SxQtg.png" srcset="https://miro.medium.com/max/552/1*ZcfEGwvoHT5QXtVW1SxQtg.png 276w, https://miro.medium.com/max/1104/1*ZcfEGwvoHT5QXtVW1SxQtg.png 552w, https://miro.medium.com/max/1280/1*ZcfEGwvoHT5QXtVW1SxQtg.png 640w, https://miro.medium.com/max/1400/1*ZcfEGwvoHT5QXtVW1SxQtg.png 700w" sizes="700px">

</p>

However, there is a problem with hashing that users who have same passwords are easy to spot. **`Password salt`** — A ***salt*** is a fixed-length cryptographically-strong random value that can be stored alongside the password (salt is usually 16, 32, or 64 bytes). Concatenate the salt and the password before hashing it

**`bcrypt`** — Password hashing function that automatically handles all password salting complexity and includes it in the hash output

**`Microsoft`**: “Based on our studies, your account is more than 99.9% less likely to be compromised if you use Multi-factor authentication”

###  Safe coding practices

**`Complexity is the enemy of security`** — The goal of abstractions is to hide complexity from the developer. The more edge cases an abstraction has the “leakier” it is.

**`Explicit code is better than clever code`** — Writing overly clever, succinct, or “magic” code can increase the complexity

**`Fail early`** — Ignore the Robustness Principle and do the opposite

**`Code defensively`** — Your assumptions may be violated, so always verify them upfront

### DNS Rebinding

<img alt="" class="nn to fe en ej jq w c" width="700" height="404" role="presentation" src="https://miro.medium.com/max/1400/1*LLo4Uh1JWu6Uhm4LpLHG-w.png" srcset="https://miro.medium.com/max/552/1*LLo4Uh1JWu6Uhm4LpLHG-w.png 276w, https://miro.medium.com/max/1104/1*LLo4Uh1JWu6Uhm4LpLHG-w.png 552w, https://miro.medium.com/max/1280/1*LLo4Uh1JWu6Uhm4LpLHG-w.png 640w, https://miro.medium.com/max/1400/1*LLo4Uh1JWu6Uhm4LpLHG-w.png 700w" sizes="700px">

</p>

**`DNS rebinding attack`** — Allows a remote attacker to bypass **`CORS`** rules, bypass the victim’s network firewall and use their web browser as a proxy to communicate directly with vulnerable servers on the local network. **`DNS rebinding`** exploits limitation in the **`Same Origin Policy`**.

**`Origin is protocol + hostname + port`**. The actual IP address that the hostname resolves to is not included.

>Don’t ship a local HTTP server with your software. If you do, you better understand DNS rebinding attacks

**`Prevent DNS rebinding`** — DNS rebinding allows the attacker to trick the browser into thinking the local victim server is the same origin to attacker.com. So ensure that the Host header is not for a random origin, but instead for localhost or equivalent. We cannot rely on Origin header since it is not sent for same origin requests

### CS 253 Key ideas

* Think like an attacker!

* Never trust user input — always sanitize it, at time of use

* Use defense-in-depth — provide redundancy in case security controls fail

* Salt and hash user passwords — “just use bcrypt!”

* Beware ambient authority — use SameSite cookies!

* Don’t write clever code — explicit code is safer than magical code

* Dangerous code should look dangerous — make it stand out

* You can never be too paranoid — practice constant vigilance

❤