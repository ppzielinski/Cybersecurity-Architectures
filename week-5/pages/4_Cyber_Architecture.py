import os
import streamlit as st
import pandas as pd
from diagrams import Diagram, Cluster
from diagrams.onprem.client import Users
from diagrams.aws.network import Route53, ElasticLoadBalancing as ElasticLoadBalancer
from diagrams.aws.compute import EC2
from diagrams.aws.storage import S3, ElasticFileSystemEFS as ElasticFileSystem
from diagrams.aws.management import Cloudwatch
from diagrams.onprem.security import Vault



# Create output directory for diagrams if it doesn't exist
if not os.path.exists("arch"):
    os.makedirs("arch")

#######################################################
# Define functions to generate each diagram
#######################################################

def generate_did_diagram():
    """Generate a Defense in Depth (DiD) diagram."""
    with Diagram("Defense in Depth", filename="arch/did_diagram", show=False, outformat="png"):
        users = Users("Clients")
        dns = Route53("DNS")
        lb = ElasticLoadBalancer("Load Balancer")
        # Web Tier cluster
        with Cluster("Web Tier"):
            web1 = EC2("Web Server 1")
            web2 = EC2("Web Server 2")
        # Application Tier cluster
        with Cluster("Application Tier"):
            app1 = EC2("App Server 1")
            app2 = EC2("App Server 2")
        # Database Tier cluster
        with Cluster("Database Tier"):
            db = EC2("Database")
        # Chain nodes individually
        users >> dns >> lb
        lb >> web1
        lb >> web2
        web1 >> app1
        web1 >> app2
        web2 >> app1
        web2 >> app2
        app1 >> db
        app2 >> db

def generate_zta_diagram():
    """Generate a Zero Trust Architecture (ZTA) diagram."""
    with Diagram("Zero Trust Architecture", filename="arch/zta_diagram", show=False, outformat="png"):
        users = Users("Users")
        idp = Vault("Identity Provider")
        lb = ElasticLoadBalancer("Load Balancer")
        # Micro-segmentation cluster (multiple zones)
        with Cluster("Micro-Segmented Zones"):
            zone1 = EC2("Zone 1")
            zone2 = EC2("Zone 2")
        users >> idp >> lb
        lb >> zone1
        lb >> zone2

def generate_ssdlc_diagram():
    """Generate a Secure Software Development Lifecycle (SSDLC) diagram."""
    with Diagram("SSDLC", filename="arch/ssdlc_diagram", show=False, outformat="png"):
        dev = Users("Developers")
        vcs = EC2("Version Control")
        ci = EC2("CI/CD Pipeline")
        testing = EC2("Testing")
        prod = EC2("Production")
        dev >> vcs >> ci >> testing >> prod

def generate_zka_diagram():
    """Generate a Zero Knowledge Architecture (ZKA) diagram."""
    with Diagram("Zero Knowledge Architecture", filename="arch/zka_diagram", show=False, outformat="png"):
        users = Users("Users")
        client_enc = EC2("Client-Side Encryption")
        storage = S3("Encrypted Storage")
        users >> client_enc >> storage

def generate_asa_diagram():
    """Generate an Adaptive Security Architecture (ASA) diagram."""
    with Diagram("Adaptive Security Architecture", filename="arch/asa_diagram", show=False, outformat="png"):
        users = Users("Users")
        telemetry = Cloudwatch("Telemetry")
        analytics = EC2("Behavior Analytics")
        response = EC2("Automated Response")
        users >> telemetry
        telemetry >> analytics >> response

#######################################################
# Generate diagrams; capture their return values to suppress output
#######################################################

_ = generate_did_diagram()
_ = generate_zta_diagram()
_ = generate_ssdlc_diagram()
_ = generate_zka_diagram()
_ = generate_asa_diagram()

#######################################################
# Define layered controls tables for each architecture
#######################################################

# Defense in Depth (DiD) controls table
did_controls = pd.DataFrame({
    "Layer": ["Network Segmentation", "Data Encryption", "Monitoring & Logging"],
    "Control": [
        "VPC segmentation, Security Groups, Subnet isolation",
        "TLS for data in transit, KMS for data at rest",
        "CloudWatch, GuardDuty, SIEM integration"
    ],
    "Rationale": [
        "Limits lateral movement if one layer is breached.",
        "Protects data confidentiality even if a breach occurs.",
        "Detects anomalies and provides early warning of breaches."
    ]
})

# Zero Trust Architecture (ZTA) controls table
zta_controls = pd.DataFrame({
    "Layer": ["Identity & Access", "Micro-Segmentation", "Continuous Verification"],
    "Control": [
        "Strong IAM policies, MFA, least privilege access",
        "Granular security groups and segmentation for workloads",
        "Regular posture assessments and logging of all requests"
    ],
    "Rationale": [
        "No entity is trusted by default; every access is verified.",
        "Limits the scope of compromise by isolating workloads.",
        "Ensures that trust is continuously re-evaluated based on context."
    ]
})

# SSDLC controls table
ssdlc_controls = pd.DataFrame({
    "Stage": ["Requirements/Design", "Development", "Testing", "Deployment"],
    "Control": [
        "Threat modeling and secure architecture reviews",
        "Static analysis (SAST) and dependency scanning",
        "Dynamic analysis (DAST) and penetration testing",
        "IaC security checks and secrets management"
    ],
    "Rationale": [
        "Identifies risks early in the design phase.",
        "Catches vulnerabilities in code before production.",
        "Validates security under realistic conditions.",
        "Prevents misconfigurations and protects sensitive data."
    ]
})

# Zero Knowledge Architecture (ZKA) controls table
zka_controls = pd.DataFrame({
    "Layer": ["Client-Side Encryption", "BYOK (Bring Your Own Key)", "Minimal Plaintext Logging"],
    "Control": [
        "Encrypt data before uploading to the cloud",
        "Integrate external key management for encryption",
        "Redact sensitive data in logs to prevent exposure"
    ],
    "Rationale": [
        "Ensures that the cloud provider never sees plaintext data.",
        "Gives the organization full control over encryption keys.",
        "Reduces the risk of sensitive data leakage via logs."
    ]
})

# Adaptive Security Architecture (ASA) controls table
asa_controls = pd.DataFrame({
    "Layer": ["Telemetry", "Behavior Analytics", "Automated Response", "Threat Intelligence"],
    "Control": [
        "Continuous monitoring using CloudWatch and GuardDuty",
        "User and entity behavior analytics (UEBA)",
        "SOAR automation for incident response",
        "Dynamic updating of defense mechanisms based on intel"
    ],
    "Rationale": [
        "Provides real-time visibility into system activity.",
        "Detects abnormal patterns that indicate compromise.",
        "Minimizes response time to detected incidents.",
        "Adapts defenses as new threat information emerges."
    ]
})

#######################################################
# Streamlit App to display the diagrams and tables
#######################################################
st.title("Security Architecture Diagrams and Layered Controls")

# Sidebar for selecting the architecture type
arch_choice = st.sidebar.selectbox(
    "Select an Architecture",
    ["Defense in Depth (DiD)", "Zero Trust Architecture (ZTA)", "SSDLC", "Zero Knowledge Architecture (ZKA)", "Adaptive Security Architecture (ASA)"]
)

# Display the corresponding table and diagram
if arch_choice == "Defense in Depth (DiD)":
    st.header("Defense in Depth (DiD)")
    st.table(did_controls)
    diagram_path = "arch/did_diagram.png"
elif arch_choice == "Zero Trust Architecture (ZTA)":
    st.header("Zero Trust Architecture (ZTA)")
    st.table(zta_controls)
    diagram_path = "arch/zta_diagram.png"
elif arch_choice == "SSDLC":
    st.header("Secure Software Development Lifecycle (SSDLC)")
    st.table(ssdlc_controls)
    diagram_path = "arch/ssdlc_diagram.png"
elif arch_choice == "Zero Knowledge Architecture (ZKA)":
    st.header("Zero Knowledge Architecture (ZKA)")
    st.table(zka_controls)
    diagram_path = "arch/zka_diagram.png"
elif arch_choice == "Adaptive Security Architecture (ASA)":
    st.header("Adaptive Security Architecture (ASA)")
    st.table(asa_controls)
    diagram_path = "arch/asa_diagram.png"

# Verify that the diagram image exists and display it
if os.path.exists(diagram_path):
    st.image(diagram_path, caption=f"{arch_choice} Diagram", use_column_width=True)
else:
    st.warning(f"Diagram not found for {arch_choice} at {diagram_path}.")
