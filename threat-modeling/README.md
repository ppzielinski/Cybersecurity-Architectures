## Cloudformation templates location

https://aws.amazon.com/cloudformation/resources/templates/govcloud-us/

---

### STRIDE Report 

---

#### Resource: InboundHTTPPublicNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Let’s dive in with the *InboundHTTPPublicNetworkAcLEntry*. The report flags that the Network ACL—or NACL—allows incoming traffic from *anywhere*—that’s 0.0.0.0/0—on port 80, the HTTP port. This raises two risks under the STRIDE model: *Information Disclosure*—where sensitive data could be exposed—and *Denial of Service*—if attackers flood the system with traffic.  
- **What to Do**: We need to review if this broad access is necessary. NACLs are typically broader than Security Groups, but *‘allow all’ rules should be intentional* and not accidentally bypass tighter controls elsewhere.  
- **Teaching Point**: This is a great chance to show students how layered security works in AWS—NACLs and Security Groups need to align!"

---

#### Resource: InboundHTTPSPublicNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Next up, the *InboundHTTPSPublicNetworkAcLEntry*. It’s a similar story: the NACL allows traffic from *anywhere* on port 443, the HTTPS port. Same risks here: *Information Disclosure* and *Denial of Service*.  
- **What to Do**: Again, we should check if this is intentional and doesn’t undermine Security Group settings.  
- **Teaching Point**: Even with encrypted traffic like HTTPS, overly permissive rules can still cause trouble. It’s a reminder that encryption doesn’t solve everything!"

---

#### Resource: InboundSSHPublicNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Now, the *InboundSSHPublicNetworkAcLEntry*—this one’s a bit alarming. The NACL allows traffic from *anywhere* on port 22, which is SSH. Since SSH is often used for admin access, this could lead to *Information Disclosure* or *Denial of Service* from unauthorized access attempts.  
- **What to Do**: We should restrict this to specific IP ranges or use a bastion host for SSH access.  
- **Teaching Point**: This is a *classic* example for students—leaving SSH wide open is a common mistake that invites attackers. It’s a perfect case study in least privilege!"

---

#### Resource: InboundEmphemeralPublicNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"For the *InboundEmphemeralPublicNetworkAcLEntry*, the NACL allows traffic from *anywhere* on ephemeral ports—1024 to 65535. These ports are often used for return traffic in client-server setups, but opening them to everyone risks *Information Disclosure* and *Denial of Service*.  
- **What to Do**: Review if this is necessary—maybe limit it to specific sources.  
- **Teaching Point**: Students can learn here about balancing functionality and security—ephemeral ports are tricky but shouldn’t be a free-for-all!"

---

#### Resource: OutboundPublicNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Moving to *OutboundPublicNetworkAcLEntry*, the NACL allows *all* outbound traffic to *anywhere* on *any* port—0 to 65535. This could enable data leaks or connections to malicious sites, triggering *Information Disclosure* or *Denial of Service*.  
- **What to Do**: Restrict outbound traffic to only what’s needed.  
- **Teaching Point**: Outbound rules are often ignored, but they’re critical—students should see how this could lead to data exfiltration!"

---

#### Resource: InboundPrivateNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Even in private subnets, the *InboundPrivateNetworkAcLEntry* allows traffic from *anywhere* on *all* ports. That’s way too open and risks *Information Disclosure* and *Denial of Service*.  
- **What to Do**: Tighten this to allow only trusted sources, like other VPC subnets.  
- **Teaching Point**: This shows students why internal resources still need protection—it’s all about defense-in-depth!"

---

#### Resource: OutBoundPrivateNetworkAcLEntry (AWS::EC2::NetworkAcLEntry)  
"Similarly, the *OutBoundPrivateNetworkAcLEntry* allows all outbound traffic from private subnets to *anywhere*. Same risks: *Information Disclosure* and *Denial of Service*.  
- **What to Do**: Limit this to specific destinations, like update servers.  
- **Teaching Point**: Another lesson in controlling data flow—private doesn’t mean unrestricted!"

---

#### Resource: NATDevice (AWS::EC2::Instance)  
"The *NATDevice* is placed in a public subnet, which makes sense—it routes traffic from private subnets to the internet. But it’s exposed, raising risks like *Information Disclosure*, *Spoofing*, *Denial of Service*, and *Tampering*.  
- **What to Do**: Secure it with tight security groups and careful management, like using a bastion host.  
- **Teaching Point**: Students can see that even utility instances need strong security—nothing’s exempt!"

---

#### Resource: NATSecurityGroup (AWS::EC2::SecurityGroup)  
"The *NATSecurityGroup* is *way* too permissive—it allows traffic from *anywhere* on ports 80, 443, and 22. That’s HTTP, HTTPS, and SSH, with risks of *Information Disclosure*, *Spoofing*, and *Denial of Service*. Plus, SSH being open to all adds *Elevation of Privilege*.  
- **What to Do**: Restrict these to known IPs or use AWS Session Manager instead of SSH. A NAT shouldn’t need inbound internet traffic!  
- **Teaching Point**: This screams least privilege—students can discuss why NATs don’t need wide-open ports!"

---

#### Resource: BastionHost (AWS::EC2::Instance)  
"The *BastionHost* is in a public subnet, which is normal—it’s a secure SSH entry point. But it’s exposed, so we’ve got *Information Disclosure*, *Spoofing*, *Denial of Service*, and *Tampering*.  
- **What to Do**: Lock it down with restrictive security groups and trusted IPs.  
- **Teaching Point**: Bastion Hosts are key but risky—students can explore secure admin access here!"

---

#### Resource: BastionSecurityGroup (AWS::EC2::SecurityGroup)  
"The *BastionSecurityGroup* allows SSH from *anywhere*—big red flag! Risks include *Information Disclosure*, *Spoofing*, *Denial of Service*, and *Elevation of Privilege*.  
- **What to Do**: Limit SSH to specific IPs or use a VPN.  
- **Teaching Point**: This is *the* example of why SSH shouldn’t be open to the world—perfect for a security lesson!"

---

#### Resource: PublicElasticLoadBalancer (AWS::ElasticLoadBalancing::LoadBalancer)  
"The *PublicElasticLoadBalancer* is internet-facing, which is fine for public apps, but it risks *Denial of Service*, *Spoofing*, and *Information Disclosure*. It also has an HTTP listener on port 80—unencrypted traffic—adding *Information Disclosure* and *Tampering*.  
- **What to Do**: Use AWS WAF for protection and switch to HTTPS with certificates from ACM.  
- **Teaching Point**: Students can learn about securing public-facing services and why encryption matters!"

---

#### Resource: PublicLoadBalancerSecurityGroup (AWS::EC2::SecurityGroup)  
"The *PublicLoadBalancerSecurityGroup* allows port 80 traffic from *anywhere*, which is typical but risks *Information Disclosure*, *Spoofing*, and *Denial of Service*.  
- **What to Do**: Restrict it if the app doesn’t need global access.  
- **Teaching Point**: A chance to discuss when to limit public access—regional apps don’t need the whole internet!"

---

#### Resource: PrivateElasticLoadBalancer (AWS::ElasticLoadBalancing::LoadBalancer)  
"The *PrivateElasticLoadBalancer* is internal—great for security—but it uses HTTP on port 80, so traffic is unencrypted, risking *Information Disclosure* and *Tampering*.  
- **What to Do**: Switch to HTTPS, even internally, for sensitive data.  
- **Teaching Point**: Encryption isn’t just for the internet—students should see its value inside the VPC too!"

---

### H1 Model Notes

Below is a conversational transcript designed for a professor to explain the threat model report provided in the query for the SEAS-8405 class. The tone is engaging and educational, with intonation cues implied through emphasis (via markdown) and teaching points to enrich the classroom experience. The report covers a system with a web server, SQL database, real identity database, AWS Lambda functions, and various data flows, analyzed under the STRIDE model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). I’ve selected key threats to discuss, ensuring the explanation is clear, manageable, and valuable for students.

---

### Transcript for Professor

#### Web Server Threats  
"Let’s kick off with the *web server*. The report lists a ton of threats, but I’ll zoom in on a few big ones. First up: *SQL Injection*. This is where attackers slip malicious SQL code into inputs—like a comment field—potentially stealing data or messing with the database. In STRIDE terms, that’s *Tampering* (altering data) and *Information Disclosure* (exposing secrets).  
- **Fix It**: Use prepared statements and parameterized queries to block bad inputs.  
- **Teaching Point**: SQL Injection is a classic vuln—students can see why validating inputs is non-negotiable!"

"Next, *Cross-Site Scripting (XSS)*. Here, attackers inject scripts into web pages—like comments shown to users—tricking browsers into running malicious code. This hits *Spoofing* (impersonating legit content), *Tampering* (altering page behavior), and *Information Disclosure* (stealing user data).  
- **Fix It**: Sanitize inputs and use Content Security Policies to limit what scripts can run.  
- **Teaching Point**: XSS teaches output encoding—students can explore how browsers parse code!"

"Finally, *Session Hijacking*. Attackers grab session tokens—like the user ID token in our data dictionary—to pretend they’re legit users. That’s *Spoofing* and *Elevation of Privilege*.  
- **Fix It**: Secure cookies, enforce HTTPS, and regenerate tokens often.  
- **Teaching Point**: This ties to session security—students can dig into protecting authentication!"

---

#### SQL Database Threats  
"Moving to the *SQL Database*, the report flags *Privilege Abuse*. If a user or process has too much access, they could misuse it—like deleting data they shouldn’t touch. This is *Tampering* and *Information Disclosure*.  
- **Fix It**: Follow the least privilege principle—only grant what’s needed.  
- **Teaching Point**: This is a perfect chance to teach least privilege—students can see how over-permission bites back!"

---

#### AWS Lambda Threats  
"For *AWS Lambda*, *Code Injection* stands out. Attackers might sneak malicious code into the serverless function—like the one cleaning the database—causing chaos. That’s *Tampering* (altering function behavior) and *Elevation of Privilege* (gaining unauthorized control).  
- **Fix It**: Validate all inputs and write secure code in those functions.  
- **Teaching Point**: Serverless isn’t a free pass—students can learn that cloud code needs securing too!"

---

#### Data Flow Threats  
"Across the *data flows*—like user comments moving to the database or back to the web server—*Interception* and *Data Leaks* are major risks. If data isn’t encrypted, attackers can snatch or tweak it. That’s *Information Disclosure* (leaking sensitive stuff) and *Tampering* (changing data in transit).  
- **Fix It**: Use TLS for data in transit and encrypt sensitive data at rest.  
- **Teaching Point**: Encryption is king—students can debate where and how to apply it!"

---

