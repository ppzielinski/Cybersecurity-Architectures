import streamlit as st
import pandas as pd

# 1. Make the page layout wide
st.set_page_config(layout="wide")

def main():
    st.title("SEAS-8405: Security Architecture Principles")

    # ----------------------------------------------------
    # 1. Defense in Depth
    #   Expanded by default
    # ----------------------------------------------------
    did_data = [
        {"Layer": "Network",     "Control Example": "VPC, subnets, NACLs, firewalls (e.g., WAF)"},
        {"Layer": "Endpoint",    "Control Example": "EDR, OS hardening, patching"},
        {"Layer": "Application", "Control Example": "Input validation, rate limiting, authz checks"},
        {"Layer": "Data",        "Control Example": "Encryption at rest & in transit, access logging"},
        {"Layer": "Monitoring",  "Control Example": "SIEM, alerting (e.g., Prometheus + Grafana)"},
        {"Layer": "Recovery",    "Control Example": "Backups, disaster recovery plans"},
    ]
    df_did = pd.DataFrame(did_data)

    did_expander = st.expander("1. Defense in Depth (DiD)", expanded=True)
    with did_expander:
        st.write("Apply controls at **multiple layers**:")
        st.table(df_did)

    # ----------------------------------------------------
    # 2. Zero Trust Architecture
    #   Collapsed by default
    # ----------------------------------------------------
    zt_data = [
        {"Principle": "Never trust, always verify", "Implementation": "MFA, device posture checks, identity-aware proxies"},
        {"Principle": "Least privilege",            "Implementation": "Fine-grained IAM roles and policies"},
        {"Principle": "Micro-segmentation",         "Implementation": "Use service meshes / network ACLs"},
        {"Principle": "Encrypt everywhere",         "Implementation": "mTLS for internal traffic"},
        {"Principle": "Continuous authz",           "Implementation": "Token expiration, adaptive access"},
    ]
    df_zt = pd.DataFrame(zt_data)

    zt_expander = st.expander("2. Zero Trust Architecture (ZTA)", expanded=False)
    with zt_expander:
        st.write("Focus on identity and continuous verification:")
        st.table(df_zt)

    # ----------------------------------------------------
    # 3. Secure Software Development Lifecycle (SSDLC)
    #   Collapsed by default
    # ----------------------------------------------------
    sdlc_data = [
        {"Phase": "Requirements",  "Security Control": "Threat modeling, misuse cases"},
        {"Phase": "Design",        "Security Control": "Architecture risk analysis, STRIDE"},
        {"Phase": "Coding",        "Security Control": "Linting, secure coding standards"},
        {"Phase": "Build/Test",    "Security Control": "SAST, DAST, dependency scanning"},
        {"Phase": "Release",       "Security Control": "Secrets scanning, IaC validation"},
        {"Phase": "Deploy",        "Security Control": "Signed builds, automated approvals"},
        {"Phase": "Monitor",       "Security Control": "Runtime security, anomaly detection"},
    ]
    df_sdlc = pd.DataFrame(sdlc_data)

    sdlc_expander = st.expander("3. Secure Software Development Lifecycle (SSDLC)", expanded=False)
    with sdlc_expander:
        st.write("Integrate security at each SDLC stage:")
        st.table(df_sdlc)

    # ----------------------------------------------------
    # 4. Zero Knowledge Architecture (ZKA)
    #   Collapsed by default
    # ----------------------------------------------------
    zka_data = [
        {"Layer": "Encryption at rest",
         "Control Description": "Client-side encryption (CSE); provider stores only ciphertext"},
        {"Layer": "Encryption in transit",
         "Control Description": "TLS/SSL for all data exchanges (e.g., HTTPS, mTLS)"},
        {"Layer": "Key Management",
         "Control Description": "End-user-controlled keys (BYOK or client-side KMS)"},
        {"Layer": "Access Control",
         "Control Description": "No privileged backdoor access; zero-access policies"},
        {"Layer": "Authentication",
         "Control Description": "Passwordless or multi-party auth with no stored secrets"},
        {"Layer": "Auditing",
         "Control Description": "Tamper-proof logging of every access attempt"},
        {"Layer": "Secure Sharing",
         "Control Description": "E2EE sharing links or proxy re-encryption"},
        {"Layer": "Zero Knowledge Proofs (ZKPs)",
         "Control Description": "Prove ownership/rights without revealing data (zk-SNARKs)"},
        {"Layer": "Local computation",
         "Control Description": "Client-side rendering, indexing, or processing (E2EE apps)"},
    ]
    df_zka = pd.DataFrame(zka_data)

    zka_expander = st.expander("4. Zero Knowledge Architecture (ZKA)", expanded=False)
    with zka_expander:
        st.write("**Goal**: Ensure that service providers or systems have *no access* to user data "
                 "— even during storage, processing, or transmission.")
        st.table(df_zka)

    # ----------------------------------------------------
    # 5. Adaptive Security Architecture (ASA)
    #   Collapsed by default
    # ----------------------------------------------------
    asa_data = [
        {"Layer": "Continuous Monitoring",
         "Control Description": "Telemetry from endpoints, network, identities (SIEM/SOAR)"},
        {"Layer": "Behavioral Analytics",
         "Control Description": "UEBA for anomaly detection"},
        {"Layer": "Context-Aware Access",
         "Control Description": "Risk-based MFA, device posture check, geo-aware policies"},
        {"Layer": "Dynamic Policy Engine",
         "Control Description": "Adjust policies based on context/past behavior"},
        {"Layer": "Deception Tech",
         "Control Description": "Honeypots or decoy environments for active threat engagement"},
        {"Layer": "Automated Response",
         "Control Description": "SOAR to auto-quarantine or block malicious activities"},
        {"Layer": "Threat Intelligence",
         "Control Description": "Feed external & internal intel into risk scoring"},
        {"Layer": "Runtime Protection",
         "Control Description": "RASP, WAF, eBPF-based defense against active threats"},
        {"Layer": "Feedback Loops",
         "Control Description": "ML + human triage; learn from attacks & refine rules"},
    ]
    df_asa = pd.DataFrame(asa_data)

    asa_expander = st.expander("5. Adaptive Security Architecture (ASA)", expanded=False)
    with asa_expander:
        st.write("**Goal**: Use continuous context and behavioral analysis to *dynamically* adjust defenses in real time.")
        st.table(df_asa)

if __name__ == "__main__":
    main()
