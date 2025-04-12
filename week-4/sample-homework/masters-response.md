# Security Architecture Analysis Report: Enhancing a Traditional Web Application on AWS

![img.png](img.png)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architectural Overview](#2-architectural-overview)  
   2.1 [Diagram Interpretation](#21-diagram-interpretation)  
   2.2 [Threat Surfaces](#22-threat-surfaces)
3. [Defense in Depth (DiD)](#3-defense-in-depth-did)  
   3.1 [Principles](#31-principles)  
   3.2 [Proposed Controls](#32-proposed-controls)
4. [Zero Trust Architecture (ZTA)](#4-zero-trust-architecture-zta)  
   4.1 [Principles](#41-principles)  
   4.2 [Proposed Controls](#42-proposed-controls)
5. [Secure Software Development Lifecycle (SSDLC)](#5-secure-software-development-lifecycle-ssdlc)  
   5.1 [Principles](#51-principles)  
   5.2 [Proposed Controls](#52-proposed-controls)
6. [Zero Knowledge Architecture (ZKA)](#6-zero-knowledge-architecture-zka)  
   6.1 [Principles](#61-principles)  
   6.2 [Proposed Controls](#62-proposed-controls)
7. [Adaptive Security Architecture (ASA)](#7-adaptive-security-architecture-asa)  
   7.1 [Principles](#71-principles)  
   7.2 [Proposed Controls](#72-proposed-controls)
8. [Synthesis & Reflection](#8-synthesis--reflection)  
   8.1 [Critical Controls](#81-critical-controls)  
   8.2 [Overlaps and Dependencies](#82-overlaps-and-dependencies)  
   8.3 [Challenges and Trade-offs](#83-challenges-and-trade-offs)
9. [References](#9-references)

---

## 1. Introduction

This report provides an in-depth security architecture analysis of a traditional web application hosted on Amazon Web
Services (AWS). The architecture leverages services  such as Amazon Route 53, AWS WAF, 
Amazon CloudFront, Application Load Balancer (ALB), EC2 instances across multiple
tiers, Amazon RDS, Amazon ElastiCache, and Amazon EFS, all within a Virtual Private Cloud (VPC) spanning two
availability zones.

The objective is to enhance the security posture of this architecture by applying five major cybersecurity 
architectures: **Defense in Depth (DiD)**, **Zero Trust Architecture (ZTA)**, 
**Secure Software Development Lifecycle (SSDLC)**, **Zero
Knowledge Architecture (ZKA)**, and **Adaptive Security Architecture (ASA)**. Each framework offers a unique perspective
on securing the application, from layered defenses to continuous verification and adaptive responses. 

---

## 2. Architectural Overview

### 2.1 Diagram Interpretation

The AWS-based web application architecture is designed for high availability and scalability, organized within a VPC
across two availability zones. Below is a detailed breakdown of its key components, their placement, and data flows:

- **Amazon Route 53**: A DNS service that resolves domain names and directs client traffic into the AWS environment. It
  serves as the entry point for web clients.
- **AWS WAF**: A web application firewall integrated with CloudFront and the ALB, filtering malicious HTTP traffic such
  as SQL injection or cross-site scripting (XSS).
- **Amazon CloudFront**: A content delivery network (CDN) that caches static content, reducing latency and mitigating
  distributed denial-of-service (DDoS) attacks.
- **AWS Certificate Manager (ACM)**: Manages SSL/TLS certificates, ensuring encrypted communication between clients and
  the application.
- **Application Load Balancer (ALB)**: Resides in public subnets across both availability zones, distributing incoming
  traffic to EC2 instances in the web tier.
- **NAT Gateways**: Deployed in public subnets, enabling outbound internet access for instances in private subnets while
  blocking inbound connections.
- **EC2 Instances (Web Tier)**: Hosted in private "web subnets," these instances handle HTTP/HTTPS requests and are
  managed by an Auto Scaling group for dynamic scaling.
- **EC2 Instances (Application Tier)**: Located in private "application subnets," these instances process business logic
  and interact with the database and file storage.
- **Amazon RDS**: A managed relational database service in private "database subnets," configured with a primary
  instance in one availability zone and a standby in another for failover.
- **Amazon ElastiCache**: An in-memory caching service (e.g., Redis or Memcached) that enhances performance by caching
  frequently accessed data, accessible to the application tier.
- **Amazon EFS**: A scalable file storage system shared across EC2 instances in the application tier, supporting
  persistent data storage.

**Subnet Structure**:

- **Public Subnets**: Host the ALB and NAT Gateways, accessible from the internet.
- **Private Subnets**: Contain the web tier (EC2), application tier (EC2), and database tier (RDS), isolated from direct
  internet access.

**Data Flows**:

- **Inbound**: Web Client → Route 53 → AWS WAF → CloudFront → ALB → Web Tier (EC2).
- **Internal**: Web Tier → Application Tier → RDS/ElastiCache/EFS.
- **Outbound**: Application Tier → NAT Gateway → Internet (e.g., for updates or external API calls).

### 2.2 Threat Surfaces

The architecture exposes several attack vectors, three of which are critical:

1. **Public-Facing Components**:
    - **Components**: ALB, AWS WAF, CloudFront, Route 53.
    - **Threats**: These internet-accessible services are prime targets for DDoS attacks, SQL injection, XSS, or DNS
      spoofing. For instance, an attacker could overwhelm CloudFront with traffic or exploit weak WAF rules.
    - **Impact**: Disruption of service availability or initial foothold for deeper attacks.

2. **EC2 Instances in Private Subnets**:
    - **Components**: Web and application tier EC2 instances.
    - **Threats**: If an attacker compromises the web tier (e.g., via a vulnerability in the application code), they
      could attempt lateral movement to the application tier or exploit misconfigured security groups. Unpatched systems
      amplify this risk.
    - **Impact**: Access to sensitive application logic or escalation to the database tier.

3. **Data Storage Services**:
    - **Components**: RDS, EFS, ElastiCache.
    - **Threats**: Misconfigured IAM roles, security groups, or lack of encryption could allow unauthorized access to
      sensitive data. For example, an overly permissive RDS security group might expose the database to internal
      threats. - **Impact**: Data exfiltration or corruption, compromising confidentiality and integrity.


---

## 3. Defense in Depth (DiD)

### 3.1 Principles

Defense in Depth (DiD) employs multiple, independent layers of security controls to protect an information system. If
one layer fails, others remain to mitigate or contain the breach. This approach aligns with NIST SP 800-53 guidelines,
emphasizing redundancy and diversity in defenses (Scarfone & Souppaya, 2009).

### 3.2 Proposed Controls

| **Control**                  | **AWS Implementation**                    | **Rationale**                                                                                                                                        |
|------------------------------|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Network Segmentation**     | VPC subnets, security groups, NACLs       | Isolates public and private subnets, restricting traffic to only necessary ports (e.g., 80, 443). Reduces lateral movement risk (Ross et al., 2019). |
| **Web Application Firewall** | AWS WAF with custom rules                 | Filters HTTP traffic for XSS, SQL injection, and DDoS attempts before reaching the ALB. Essential for edge protection (OWASP, 2021).                 |
| **Intrusion Detection**      | Amazon GuardDuty, VPC Flow Logs           | Detects anomalous activities (e.g., unusual traffic patterns) across the VPC, enhancing visibility (Scarfone & Mell, 2007).                          |
| **Encryption**               | TLS via ACM, RDS/EFS encryption at rest   | Protects data in transit and at rest, ensuring confidentiality even if other layers are breached (Stallings, 2017).                                  |
| **Endpoint Hardening**       | EC2 patch management, hardened AMIs       | Minimizes vulnerabilities on web and app servers, reducing exploitability (Ross et al., 2019).                                                       |
| **Backup and Recovery**      | RDS snapshots, EFS backups, S3 versioning | Ensures data availability and integrity post-incident, supporting resilience (NIST SP 800-34, 2010).                                                 |

**Detailed Explanation**:

- **Network Segmentation**: By leveraging VPC subnets and security groups, traffic between the web tier, application
  tier, and database tier is tightly controlled. For example, the RDS subnet only allows port 3306 from the application
  tier, thwarting unauthorized access attempts.
- **WAF**: Custom rules can block known attack signatures, while rate-limiting mitigates DDoS risks, protecting the ALB
  and downstream services.
- **Encryption**: TLS ensures secure client-to-ALB communication, while RDS encryption with AWS KMS safeguards stored
  data, critical given the sensitivity of database contents.

---

## 4. Zero Trust Architecture (ZTA)

### 4.1 Principles

Zero Trust Architecture (ZTA) operates on the principle of "never trust, always verify," assuming no entity—inside or
outside the network—is inherently trustworthy. It emphasizes identity verification, micro-segmentation, and continuous
monitoring, as outlined in NIST SP 800-207 (Rose et al., 2020).

### 4.2 Proposed Controls

| **Control**                  | **AWS Implementation**                  | **Rationale**                                                                                         |
|------------------------------|-----------------------------------------|-------------------------------------------------------------------------------------------------------|
| **IAM with Least Privilege** | Role-based access, MFA for admins       | Ensures only authorized entities access resources, reducing insider threat risks (Rose et al., 2020). |
| **Micro-Segmentation**       | Security groups, network ACLs           | Limits communication to explicit, minimal flows, preventing lateral movement (Kindervag, 2010).       |
| **Mutual TLS (mTLS)**        | ACM certificates for app-to-RDS traffic | Verifies both endpoints in internal communications, enhancing trust enforcement (Stallings, 2017).    |
| **Continuous Monitoring**    | CloudTrail, GuardDuty, Security Hub     | Tracks all actions and anomalies, enabling real-time verification of trust (Rose et al., 2020).       |
| **Endpoint Security**        | AWS Systems Manager, security agents    | Ensures EC2 instances meet compliance standards, blocking untrusted nodes (Kindervag, 2010).          |

**Detailed Explanation**:

- **IAM**: Policies restrict EC2 instances to specific RDS actions (e.g., `rds:DescribeDBInstances`), while MFA adds a
  second authentication layer for human users.
- **Micro-Segmentation**: Security groups ensure the web tier only communicates with the ALB and application tier, not
  directly with RDS, aligning with ZTA’s granular control.
- **Continuous Monitoring**: CloudTrail logs API calls, while GuardDuty analyzes VPC Flow Logs for threats, ensuring
  ongoing validation of system behavior.

---

## 5. Secure Software Development Lifecycle (SSDLC)

### 5.1 Principles

The Secure Software Development Lifecycle (SSDLC) integrates security into every phase of software
development—requirements, design, coding, testing, deployment, and maintenance. It aims to proactively identify and
mitigate vulnerabilities, as advocated by OWASP’s Software Assurance Maturity Model (SAMM) (OWASP, 2021).

### 5.2 Proposed Controls

| **Control**             | **AWS Implementation**                         | **Rationale**                                                                                     |
|-------------------------|------------------------------------------------|---------------------------------------------------------------------------------------------------|
| **Threat Modeling**     | During design, using STRIDE or PASTA           | Identifies risks (e.g., ALB DDoS, RDS injection) early, informing secure design (Shostack, 2014). |
| **SAST**                | CodeCommit with CodeGuru Reviewer              | Detects coding flaws (e.g., XSS) in application code before deployment (Chess & McGraw, 2004).    |
| **DAST**                | Post-deployment testing with third-party tools | Validates runtime security, catching issues missed by static analysis (OWASP, 2021).              |
| **Dependency Scanning** | CodeBuild with Dependabot or Snyk              | Prevents use of vulnerable libraries, critical for EC2-hosted apps (Chess & McGraw, 2004).        |
| **IaC Scanning**        | CloudFormation templates with cfn-nag          | Ensures infrastructure (e.g., security groups) is securely configured (Shostack, 2014).           |
| **Secrets Management**  | AWS Secrets Manager                            | Securely stores and rotates credentials, avoiding hardcoding (OWASP, 2021).                       |

**Detailed Explanation**:

- **Threat Modeling**: Using STRIDE, potential threats like spoofing (Route 53) or tampering (RDS) are mapped, guiding
  control placement.
- **SAST/DAST**: Static scans identify insecure code patterns, while dynamic tests simulate attacks on the running
  application, ensuring robust security.
- **IaC Scanning**: Tools like cfn-nag flag overly permissive security groups, preventing misconfigurations in the VPC
  setup.

---

## 6. Zero Knowledge Architecture (ZKA)

### 6.1 Principles

Zero Knowledge Architecture (ZKA) ensures that service providers and administrators cannot access user data in
plaintext, relying on client-side encryption and minimal data exposure. While challenging in a managed cloud like AWS,
approximations are feasible (Diffie & Hellman, 1976).

### 6.2 Proposed Controls

| **Control**                   | **AWS Implementation**                   | **Rationale**                                                                                    |
|-------------------------------|------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Client-Side Encryption**    | Encrypt data before upload to EFS/S3     | Prevents AWS from accessing plaintext, preserving confidentiality (Diffie & Hellman, 1976).      |
| **Bring Your Own Key (BYOK)** | Customer-managed keys in AWS KMS         | Limits AWS’s decryption capability, aligning with ZKA principles (Stallings, 2017).              |
| **Minimal Data Exposure**     | Redact sensitive data in CloudWatch logs | Ensures logs reveal only metadata, not content, reducing insider risks (Diffie & Hellman, 1976). |

**Detailed Explanation**:

- **Client-Side Encryption**: Application-tier EC2 instances encrypt data using a client-held key before storage,
  ensuring AWS only sees ciphertext.
- **BYOK**: External key management with KMS allows customers to retain control, though AWS still manages the
  infrastructure, limiting true zero knowledge.
- **Minimal Data Exposure**: Logging configurations exclude sensitive fields (e.g., user data), maintaining privacy even
  under audit.

---

## 7. Adaptive Security Architecture (ASA)

### 7.1 Principles

Adaptive Security Architecture (ASA) focuses on continuous monitoring, real-time threat detection, and automated
responses to evolving threats. It aligns with the dynamic nature of cloud environments (Hutchinson & Ophoff, 2018).

### 7.2 Proposed Controls

| **Control**                     | **AWS Implementation**                       | **Rationale**                                                                                              |
|---------------------------------|----------------------------------------------|------------------------------------------------------------------------------------------------------------|
| **Real-Time Threat Detection**  | Amazon GuardDuty, Security Hub               | Identifies threats (e.g., compromised EC2) instantly, enabling rapid response (Hutchinson & Ophoff, 2018). |
| **Automated Incident Response** | Lambda triggers for GuardDuty findings       | Automatically isolates affected resources, reducing attack dwell time (NIST SP 800-61, 2012).              |
| **Behavioral Analytics**        | CloudWatch anomalies, third-party UEBA tools | Detects deviations (e.g., unusual RDS queries), enhancing threat visibility (Hutchinson & Ophoff, 2018).   |
| **Dynamic Access Controls**     | IAM policies adjusted via AWS Config         | Adapts permissions based on risk, ensuring security aligns with current threats (NIST SP 800-61, 2012).    |

**Detailed Explanation**:

- **Threat Detection**: GuardDuty analyzes VPC Flow Logs and CloudTrail, flagging suspicious activities like
  unauthorized API calls.
- **Automated Response**: A Lambda function could terminate a compromised EC2 instance or tighten security group rules
  upon detection.
- **Behavioral Analytics**: Monitoring baselines (e.g., typical ALB traffic) allows anomaly detection, critical for
  adaptive defense.

---

## 8. Synthesis & Reflection

### 8.1 Critical Controls

- **Network Segmentation (DiD, ZTA)**: Essential for isolating public-facing ALB and private RDS, minimizing attack
  propagation.
- **Continuous Monitoring (ZTA, ASA)**: Vital for detecting threats across CloudFront, EC2, and RDS in real time.
- **Encryption (DiD, ZKA)**: Protects data confidentiality, especially in RDS and EFS, against breaches.

### 8.2 Overlaps and Dependencies

- **Segmentation**: DiD’s subnet isolation supports ZTA’s micro-segmentation, both relying on security groups.
- **Monitoring**: ZTA’s continuous verification feeds ASA’s adaptive responses, both leveraging CloudTrail and
  GuardDuty.
- **Encryption**: DiD and ZKA overlap in protecting data at rest, with ZKA adding client-side complexity.

### 8.3 Challenges and Trade-offs

- **Complexity**: Managing multiple controls (e.g., WAF rules, IAM policies) increases operational overhead.
- **Performance**: Encryption and mTLS may introduce latency, particularly for real-time applications.
- **Cost**: Services like GuardDuty, Security Hub, and frequent backups raise expenses, requiring budget justification.
- **ZKA Limitations**: True zero knowledge is impractical in AWS due to managed service dependencies, necessitating
  trade-offs in control.

---

## 9. References

- Chess, B., & McGraw, G. (2004). Static analysis for security. *IEEE Security & Privacy*, 2(6), 76-79.
- Diffie, W., & Hellman, M. (1976). New directions in cryptography. *IEEE Transactions on Information Theory*, 22(6),
  644-654.
- Hutchinson, D., & Ophoff, J. (2018). Adaptive security architecture: A review. *Computers & Security*, 75, 1-12.
- Kindervag, J. (2010). *No More Chewy Centers: Introducing the Zero Trust Model*. Forrester Research.
- NIST SP 800-34. (2010). *Contingency Planning Guide for Federal Information Systems*. National Institute of Standards
  and Technology.
- NIST SP 800-61. (2012). *Computer Security Incident Handling Guide*. National Institute of Standards and Technology.
- NIST SP 800-207. (2020). *Zero Trust Architecture*. National Institute of Standards and Technology.
- OWASP. (2021). *OWASP Software Assurance Maturity Model (SAMM)*. Retrieved from https://owaspsamm.org/
- Rose, S., et al. (2020). *Zero Trust Architecture*. NIST Special Publication 800-207.
- Ross, R., et al. (2019). *Systems Security Engineering*. NIST Special Publication 800-160.
- Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems*. NIST SP 800-94.
- Scarfone, K., & Souppaya, M. (2009). *Guide to Security for Full Virtualization Technologies*. NIST SP 800-125.
- Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley.
- Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice*. Pearson.

