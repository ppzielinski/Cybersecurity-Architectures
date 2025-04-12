import streamlit as st
import pandas as pd

st.set_page_config(layout="wide", initial_sidebar_state="expanded", page_title="Architecture Principles")
def main():
    st.title("SEAS-8405: Security Architecture Explorer")

    # Data for each architecture
    data = {
        "frameworks_vs_architecture": {
            "definition": {
                "framework": (
                    "A structured collection of guidelines, standards, and best practices "
                    "for managing cybersecurity risks (defines 'what' should be protected)."
                ),
                "architecture": (
                    "A systematic design and approach for implementing security solutions "
                    "within technology systems (defines 'how' security measures are organized)."
                )
            },
            "examples": {
                "framework": [
                    "NIST Cybersecurity Framework (CSF)",
                    "ISO/IEC 27001",
                    "CIS Controls",
                    "MITRE ATT&CK"
                ],
                "architecture": [
                    "Zero Trust Architecture (ZTA)",
                    "Defense in Depth (DiD)",
                    "TOGAF Security Architecture",
                    "SABSA"
                ]
            }
        },

        "architectures": [
            {
                "name": "Model-View-Controller (MVC)",
                "core_principles": [
                    "Separation of Concerns: Model (data), View (UI), Controller (logic)",
                    "Modularity: Independent development/testing of components",
                    "Reusability: Shared data models or controllers across different views"
                ],
                "when_to_use": [
                    "Web applications with clear separation of data, presentation, and logic",
                    "GUI apps needing modular, testable design"
                ],
                "when_not_to_use": [
                    "Very simple scripts where MVC overhead is unnecessary",
                    "Highly coupled, single-layer applications"
                ],
                "appropriate_platforms": [
                    "Web frameworks (Flask, Django, Ruby on Rails, ASP.NET)",
                    "GUI frameworks"
                ],
                "security_implications": {
                    "model": "Secure database interaction, data validation",
                    "view": "Output encoding to prevent XSS, no sensitive info leakage",
                    "controller": "Input validation, authorization checks, rate limiting"
                },
                "issues_considerations": [
                    "Overhead for small apps",
                    "Learning curve for teams",
                    "Fat controller if business logic isn’t placed in Model",
                    "Risk of SQL injection or XSS if validation/encoding is weak"
                ],
                "known_incidents": (
                    "Web app breaches often involve injection (SQLi) or XSS due to improper "
                    "MVC validation/encoding."
                ),
                "references": [
                    "Design Patterns (Gang of Four)",
                    "OWASP Secure Design Principles"
                ]
            },
            {
                "name": "Defense in Depth (DiD)",
                "core_principles": [
                    "Multiple, independent security layers",
                    "Redundancy and diversity of controls",
                    "Comprehensive coverage across network, endpoint, application, data"
                ],
                "when_to_use": [
                    "General-purpose enterprise security",
                    "Protecting high-value assets or critical infrastructure"
                ],
                "when_not_to_use": [
                    "Very low-risk environments with limited budgets",
                    "Latency-sensitive stacks where many layers might cause overhead"
                ],
                "appropriate_platforms": [
                    "Cloud (AWS, Azure, GCP)",
                    "On-prem or Hybrid data centers"
                ],
                "aws_azure_controls_table": [
                    {
                        "layer": "User Access",
                        "aws": "IAM policies, MFA",
                        "azure": "Azure AD, MFA",
                        "purpose": "Least privilege and identity verification"
                    },
                    {
                        "layer": "Network Perimeter",
                        "aws": "Security Groups, NACLs, ELB, VPC",
                        "azure": "NSGs, Azure Firewall, Azure Load Balancer, VNet",
                        "purpose": "Define trusted boundaries and control traffic"
                    },
                    {
                        "layer": "Threat Detection",
                        "aws": "GuardDuty, Inspector, Macie",
                        "azure": "Azure Defender, Sentinel",
                        "purpose": "Detect malware, data exposure, anomalies"
                    }
                    # Add more layers if desired
                ],
                "issues_considerations": [
                    "Complexity in managing multiple layers",
                    "Cost overhead",
                    "Misconfigurations leading to layered failures",
                    "Stale monitoring or ignoring alerts"
                ],
                "known_incidents": [
                    "Target breach (2013) due to weak segmentation and endpoint compromise",
                    "Equifax breach (2017) due to unpatched vulnerability in web application layer"
                ],
                "references": [
                    "NIST SP 800-53",
                    "CIS Controls"
                ]
            },
            {
                "name": "Zero Trust Architecture (ZTA)",
                "core_principles": [
                    "Never trust, always verify",
                    "Least privilege access",
                    "Micro-segmentation",
                    "Continuous authorization and monitoring"
                ],
                "when_to_use": [
                    "Distributed, remote-first, hybrid cloud environments",
                    "Protecting sensitive data with modern IAM solutions"
                ],
                "when_not_to_use": [
                    "Very small/static environments lacking IAM capabilities",
                    "Legacy systems without robust identity or segmentation"
                ],
                "appropriate_platforms": [
                    "Cloud-native, SaaS, Hybrid setups",
                    "Environments with strong identity frameworks (Okta, Azure AD)"
                ],
                "aws_azure_controls_table": [
                    {
                        "pillar": "Identity Verification",
                        "aws": "IAM Identity Center",
                        "azure": "Azure AD",
                        "purpose": "Ensure strong auth (MFA) & least privilege"
                    },
                    {
                        "pillar": "Device Trust",
                        "aws": "Inspector",
                        "azure": "Azure Security Center / Intune",
                        "purpose": "Verify endpoint posture"
                    },
                    {
                        "pillar": "Micro-Segmentation",
                        "aws": "VPC, Security Groups",
                        "azure": "VNet, NSGs, Azure Firewall",
                        "purpose": "Limit lateral movement"
                    }
                    # Add more pillars if desired
                ],
                "issues_considerations": [
                    "Integration complexity with legacy systems",
                    "User friction from frequent MFA prompts",
                    "Overreliance on identity proxies or mismanaged token expiration"
                ],
                "known_incidents": [
                    "Okta token abuse (2023) highlighted identity compromises",
                    "Colonial Pipeline (2021) used compromised credentials—need strong auth"
                ],
                "references": [
                    "NIST SP 800-207",
                    "Google BeyondCorp"
                ]
            },
            {
                "name": "Secure Software Development Lifecycle (SSDLC)",
                "core_principles": [
                    "Security by Design",
                    "Shift Left (address security early)",
                    "Continuous testing (SAST, DAST, dependency checks)",
                    "Risk management at each phase"
                ],
                "when_to_use": [
                    "Any software-producing organization",
                    "Especially for sensitive or high-risk environments"
                ],
                "when_not_to_use": [
                    "Rarely optional—though minimal for small, low-risk or internal-only code",
                    "One-off scripts with no real exposure (still, basic checks apply)"
                ],
                "appropriate_platforms": [
                    "CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions, Azure DevOps)",
                    "DevOps & DevSecOps environments"
                ],
                "aws_azure_controls_table": [
                    {
                        "phase": "Secure Development",
                        "aws": "CodeCommit, CodeGuru, 3rd-party scanners",
                        "azure": "Azure Repos, DevOps SAST/DAST",
                        "purpose": "Identify coding vulnerabilities early"
                    },
                    {
                        "phase": "Build & Deploy",
                        "aws": "CodePipeline, CodeBuild, CodeDeploy",
                        "azure": "Azure Pipelines",
                        "purpose": "Automate security gates in CI/CD"
                    },
                    {
                        "phase": "Monitoring",
                        "aws": "CloudWatch, GuardDuty, Macie",
                        "azure": "Azure Monitor, Azure Defender, Sentinel",
                        "purpose": "Continuous anomaly detection"
                    }
                    # Add more if desired
                ],
                "issues_considerations": [
                    "Cultural shift for developers (DevSecOps)",
                    "Time & resource investment",
                    "Skipping threat modeling or ignoring library vulnerabilities",
                    "Malicious code injection (SolarWinds case)"
                ],
                "known_incidents": [
                    "SolarWinds (build pipeline compromise)",
                    "Heartbleed (OpenSSL coding flaw), Adobe Flash vulnerabilities"
                ],
                "references": [
                    "OWASP SAMM",
                    "NIST SSDF (SP 800-218)"
                ]
            },
            {
                "name": "Zero Knowledge Architecture (ZKA)",
                "core_principles": [
                    "Provider never sees or decrypts user data",
                    "Client-side or end-to-end encryption (E2EE)",
                    "User-held keys (BYOK)",
                    "Zero-Knowledge Proofs (ZKPs) for access/auth without revealing data"
                ],
                "when_to_use": [
                    "Privacy-focused apps needing full data confidentiality",
                    "End-to-end encrypted messaging, secure file storage"
                ],
                "when_not_to_use": [
                    "Apps requiring server-side plaintext processing or analytics",
                    "Environments needing robust server-side search/indexing on unencrypted data"
                ],
                "appropriate_platforms": [
                    "Encrypted messaging (Signal, ProtonMail)",
                    "Client-side encryption (S3 or Azure Blob with BYOK)"
                ],
                "aws_azure_controls_table": [
                    {
                        "control": "Client-Side Encryption (CSE)",
                        "aws": "S3 client-side encryption, KMS external mode",
                        "azure": "Azure Blob with BYOK",
                        "purpose": "Cloud provider never sees plaintext"
                    },
                    {
                        "control": "Key Ownership",
                        "aws": "AWS KMS (external), CloudHSM",
                        "azure": "Azure Key Vault (HSM-backed customer keys)",
                        "purpose": "User fully controls cryptographic keys"
                    },
                    {
                        "control": "Zero Knowledge Proofs",
                        "aws": "zk-SNARK APIs, custom integration",
                        "azure": "Custom code/VMs with zk support",
                        "purpose": "Prove identity/rights without revealing data"
                    }
                ],
                "issues_considerations": [
                    "Limited server-side functionality (search, ML) with encrypted data",
                    "Key management complexity—key loss = permanent data loss",
                    "Integration challenges with third-party services expecting plaintext"
                ],
                "known_incidents": (
                    "Metadata exposure in encrypted email services; law enforcement cannot decrypt "
                    "data without user keys."
                ),
                "references": [
                    "ProtonMail Security Whitepaper",
                    "Signal Technical Docs",
                    "zk-SNARKs research"
                ]
            },
            {
                "name": "Adaptive Security Architecture (ASA)",
                "core_principles": [
                    "Real-time telemetry + contextual decisions",
                    "Behavioral analytics (UEBA) for anomalies",
                    "Continuous monitoring with dynamic policy enforcement",
                    "Automated response (SOAR)"
                ],
                "when_to_use": [
                    "High-risk or heavily regulated environments",
                    "Systems needing rapid threat detection and response"
                ],
                "when_not_to_use": [
                    "Very small orgs lacking resources for complex monitoring",
                    "Low-risk static apps with minimal runtime exposure"
                ],
                "appropriate_platforms": [
                    "SIEM/SOAR (e.g. Splunk, Sentinel, AWS GuardDuty, etc.)",
                    "Endpoints with EDR, ML-powered threat detection"
                ],
                "aws_azure_controls_table": [
                    {
                        "control": "Telemetry Collection",
                        "aws": "CloudWatch, GuardDuty, CloudTrail",
                        "azure": "Azure Monitor, Defender, Sentinel",
                        "purpose": "Gather logs/events for analysis"
                    },
                    {
                        "control": "Behavioral Analytics",
                        "aws": "Macie, Lookout for Metrics, GuardDuty UEBA",
                        "azure": "Microsoft Defender for Cloud UEBA, Sentinel",
                        "purpose": "Detect anomalies in user/entity behavior"
                    },
                    {
                        "control": "Automated Response",
                        "aws": "SOAR via EventBridge, Lambda",
                        "azure": "Sentinel Playbooks (Logic Apps)",
                        "purpose": "Immediate threat containment"
                    }
                ],
                "issues_considerations": [
                    "Integration complexity and alert fatigue",
                    "Privacy trade-offs with extensive monitoring",
                    "False positives can disrupt operations if automated incorrectly"
                ],
                "known_incidents": [
                    "Capital One (2019) had SIEM alerts not acted on promptly",
                    "Equifax (2017) failed to adapt to known vulnerability threats"
                ],
                "references": [
                    "Gartner Adaptive Security Architecture",
                    "MITRE D3FEND"
                ]
            }
        ],

        "solarwinds_sunburst_supply_chain_attack": {
            "description": (
                "A sophisticated state-sponsored supply chain attack discovered in December 2020, "
                "where the SolarWinds Orion updates were trojanized with a backdoor (SUNBURST). "
                "Attackers compromised the build system, injected malicious code, "
                "and distributed it with legitimate digital certificates."
            ),
            "attack_flow": [
                "Initial Access via weak credentials or vulnerabilities",
                "Build system compromise (injected malicious code into Orion)",
                "Malicious DLL signed and distributed as a legitimate update",
                "Dormancy period to evade detection",
                "Selective second-stage payloads (e.g., TEARDROP, RAINDROP)",
                "Lateral movement and data exfiltration"
            ],
            "architectural_failure_points": [
                "Inadequate segmentation of build servers",
                "Insufficient monitoring and alerting on code/signing processes",
                "Weak credential management (e.g. 'solarwinds123')",
                "Lack of Zero Trust principles (excessive trust in internal networks)"
            ],
            "mitigation_perspective": {
                "defense_in_depth": [
                    "Segment build environment from corporate network",
                    "Strict egress filtering and micro-segmentation",
                    "Hardening and monitoring of build servers with EDR",
                    "File integrity monitoring on source code and build outputs"
                ],
                "zero_trust_architecture": [
                    "Strong MFA, least privilege for developers/CI pipelines",
                    "Micro-segmentation of build/signing infrastructure",
                    "Continuous verification of code signing requests"
                ],
                "ssdlc_lesson": [
                    "Secure build pipeline with integrity checks",
                    "Enforce code reviews and threat modeling around build processes",
                    "Signed artifacts with strict cryptographic controls (HSMs)"
                ]
            }
        }
    }


    # Convert data to DataFrame
    # 2. Convert to DataFrame
    architectures_list = data["architectures"]
    df = pd.DataFrame(architectures_list)

    # 3. Flatten list-of-string columns
    list_cols = [
        'core_principles',
        'when_to_use',
        'when_not_to_use',
        'appropriate_platforms',
        'issues_considerations',
        'known_incidents',
        'references',
    ]
    for col in list_cols:
        df[col] = df[col].apply(lambda x: ",\n".join(x) if isinstance(x, list) else "")

    # # Suppose df_arch is your DataFrame and "core_principles" is a list of strings.
    # df_arch["core_principles"] = df_arch["core_principles"].apply(
    #     lambda items: "\n".join(items) if isinstance(items, list) else items
    # )


    # st.write(df.columns)
    # Convert "Architecture" column to index
    df.set_index("name", inplace=True)

    # Let the user select multiple columns
    available_columns = df.columns.tolist()
    selected_columns = st.multiselect(
        "Select columns to display:",
        available_columns,
        default=available_columns[:2]  # Provide some initial defaults if you like
    )

    # Display the filtered DataFrame based on the selected columns
    if selected_columns:
        st.subheader("Filtered Data:")
        st.table(df[selected_columns])
    else:
        st.write("Please select at least one column to display.")

if __name__ == "__main__":
    main()
