# suricata_Network-based attacks

## Tuned Rules for Network-Based Attack Detection 


* Example 1: TCP Port Scan Detection
* Triggers if 5 SYN packets are sent from a single source within 3 seconds.
```
alert tcp any any -> any any (
    msg:"Potential TCP Port Scan Detected";
    flags:S;
    threshold: type both, track by_src, count 5, seconds 3;
    sid:1000001;
    rev:1;
)
```
* Example 2: SYN Flood (DoS) Detection
*Triggers if 100 SYN packets are received from the same source in 1 second.
```
alert tcp any any -> any any (
    msg:"Possible SYN Flood Attack Detected";
    flags:S;
    threshold: type both, track by_src, count 100, seconds 1;
    sid:1000002;
    rev:1;
)
```
* Example 3: Suspicious DNS Query Detection
*Alerts on potential DNS tunneling by checking for specific DNS query patterns.
```
alert udp any any -> any 53 (
    msg:"Suspicious DNS Query - Possible DNS Tunneling";
    content:"|00 00 29|";
    offset:2;
    depth:3;
    threshold: type both, track by_src, count 10, seconds 60;
    sid:1000003;
    rev:1;
)
```
* Example 4: ICMP Flood Detection
* Detects a potential ICMP flood attack if 20 or more ICMP packets are sent from a single source in 2 seconds.
```
alert icmp any any -> any any (
    msg:"Possible ICMP Flood Detected";
    threshold: type both, track by_src, count 20, seconds 2;
    sid:1000004;
    rev:1;
)
```
* Example 5: UDP Flood Detection
#Alerts when 50 UDP packets are received from the same source within 1 second.
```
alert udp any any -> any any (
    msg:"Potential UDP Flood Attack Detected";
    threshold: type both, track by_src, count 50, seconds 1;
    sid:1000005;
    rev:1;
)
```
* Example 6: SMB Brute Force or Scanning Detection
#Detects potential SMB brute force attempts or scanning on port 445 if 10 connections are made within 60 seconds.
```
alert tcp any any -> any 445 (
    msg:"Possible SMB Brute Force or Scanning Activity";
    flow:to_server,established;
    content:"|FF 53 4D 42|";  # Typical SMB header
    threshold: type both, track by_src, count 10, seconds 60;
    sid:1000006;
    rev:1;
)
```

---

### How to Use This File

1. **Save the File:**  
   Save the above content into a file named `tuned_rules.rules`.

2. **Place the File in Your Rules Directory:**  
   Move or copy the file to your Suricata rules directory (e.g., `/etc/suricata/rules/`).

3. **Include the File in Your Suricata Configuration:**  
   In your `suricata.yaml` file, include this rule file by adding it to the rule files section. For example:
   ```yaml
   rule-files:
     - tuned_rules.rules
   ```
4. **Test the Configuration:**  
   Run a configuration test to ensure there are no syntax errors:
   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml
   ```

5. **Restart Suricata:**
   Once the configuration test passes, restart Suricata to apply the new rules.
