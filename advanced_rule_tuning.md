# Advanced Rule Tuning for Suricata

This guide provides a collection of advanced and unique rule tuning examples for Suricata. These techniques are designed to reduce false positives, improve detection accuracy, and add flexibility to your IDS setup. Test these in your lab environment and adjust parameters as needed.

---

## 1. Dynamic Suppression Based on Time and Source

Suppress repeated alerts from a specific source during business hours to reduce noise from known benign traffic.

```yaml
suppress gen_id 1, sig_id 2000100, track by_src, ip 192.168.1.150, time "09:00-17:00"
```
Explanation: Alerts for signature 2000100 from IP 192.168.1.150 will be suppressed during 9 AM–5 PM.

## 2. Chained Conditions for Multi-Stage Attack Detection
Combine conditions to better target multi-stage attacks. This rule alerts on HTTP traffic that accesses a sensitive URI and includes a suspicious header.
```
alert tcp $HOME_NET any -> any 80 (
    msg:"Multi-stage HTTP attack: suspicious admin access with odd headers"; 
    flow:established, to_server;
    content:"/admin"; http_uri;
    content:"X-Suspicious-Header:"; fast_pattern, nocase;
    threshold:type both, track by_src, count 3, seconds 120;
    sid:2000101;
    rev:1;
)
```
Explanation: Triggers if a source makes three HTTP requests to /admin with a suspicious header within 120 seconds.
## 3. Metadata-Enhanced Rule with Custom Variables
Use variables and metadata to target uncommon patterns and provide additional context.
```
var SENSITIVE_DIR /secret

alert tcp $HOME_NET any -> any 80 (
    msg:"Access attempt to sensitive directory detected"; 
    flow:established, to_server;
    content:"GET"; http_method;
    content:$SENSITIVE_DIR; http_uri;
    metadata:service http, category suspicious-activity, deployment lab;
    threshold:type both, track by_src, count 2, seconds 60;
    sid:2000102;
    rev:1;
)
```
Explanation: Monitors GET requests accessing the sensitive directory defined by SENSITIVE_DIR. Uses metadata to tag the alert and limits triggers.
## 4. Adaptive Content Matching with Regular Expressions
Employ regex to catch variations of attack patterns that may bypass simple string matching.
```
alert http any any -> any any (
    msg:"Adaptive SQL injection attempt detected"; 
    flow:established, to_server;
    pcre:"/((\%27)|(\'))((\s)|(\/\*)|(and)|(or))((\s)|(\%27)|(\'))/i";
    threshold:type both, track by_src, count 4, seconds 90;
    sid:2000103;
    rev:1;
)
```
Explanation: The PCRE matches multiple patterns common in SQL injection attempts. Alerts trigger if four occurrences occur from the same source within 90 seconds.
## 5. Adaptive XSS Detection Using PCRE
Detect cross-site scripting (XSS) attempts by matching variations in script tags.
```
alert http any any -> any any (
    msg:"XSS attempt detected"; 
    flow:established, to_server;
    pcre:"/<script.*?>.*?<\/script>/i";
    threshold:type both, track by_src, count 3, seconds 60;
    sid:2000104;
    rev:1;
)
```
Explanation: This rule uses a regex to catch various forms of <script> tags, triggering after three events in 60 seconds.
## 6. Conditional Byte Testing in TLS Handshake
Use byte tests to identify anomalies in protocol handshakes. This rule looks for unusually long TLS handshake messages.
```
alert tcp any any -> any 443 (
    msg:"Suspicious TLS handshake length detected"; 
    flow:established, to_server;
    byte_test: 2, >, 150, 34, relative;
    content:"ClientHello";
    sid:2000105;
    rev:1;
)
```
Explanation: The byte_test inspects 2 bytes at an offset relative to the match. If the handshake length exceeds 150 bytes, the rule triggers, indicating a potential anomaly.


