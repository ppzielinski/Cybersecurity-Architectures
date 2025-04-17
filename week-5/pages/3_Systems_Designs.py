from diagrams import Diagram, Cluster
from diagrams.onprem.client import Users
from diagrams.onprem.network import Haproxy, Nginx
from diagrams.onprem.dns import Coredns
from diagrams.onprem.storage import CEPH as Nfs, Glusterfs, CEPH as NetworkFileSystem
from diagrams.onprem.compute import Server as Vagrant
from diagrams.onprem.container import K3S as Kubernetes
from diagrams.onprem.database import Postgresql, Mongodb, Cassandra
from diagrams.onprem.inmemory import Redis
from diagrams.onprem.monitoring import Prometheus, Grafana, Zabbix
from diagrams.onprem.logging import RSyslog as Elasticsearch
from diagrams.onprem.security import Vault
from diagrams.onprem.gitops import ArgoCD as Jenkins
from diagrams.onprem.vcs import Git
from diagrams.aws.compute import EC2, Lambda, EKS as ElasticKubernetesService
from diagrams.aws.network import ELB as ElasticLoadBalancer, Route53, APIGateway, CloudFront
from diagrams.aws.storage import S3 as SimpleStorageService, EFS as ElasticFileSystem
from diagrams.aws.database import RDS as RelationalDatabaseService, Dynamodb, Redshift
from diagrams.aws.security import SecretsManager
from diagrams.aws.management import Cloudwatch
from diagrams.azure.compute import VM as VirtualMachine, AKS as AzureKubernetesService, FunctionApps as Functions
from diagrams.azure.network import LoadBalancers as AzureLB, LoadBalancers as AzureLoadBalancer, DNSZones as AzureDNSZones, DNSZones as AzureDNS, ApplicationGateway
from diagrams.azure.storage import BlobStorage
from diagrams.azure.database import DatabaseForPostgresqlServers as AzureDatabaseForPostgreSQL, CosmosDb
from diagrams.azure.analytics import DataLakeStoreGen1 as DataLakeStorage
from IPython.display import Image, display
import os


# Create output directory
if not os.path.exists("arch"):
    os.makedirs("arch")

import streamlit as st
import os

st.set_page_config(layout="wide", initial_sidebar_state="expanded", page_title="Systems Architecture")

# Define all 50 deployments with descriptions and expanded components
deployments = {
    "Web Service": {
        "description": "Delivers static and dynamic web content to users with load balancing, multiple servers, and storage for assets.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "Web Server Cluster", [(Nginx, "Nginx Server 1"), (Nginx, "Nginx Server 2"), (Nginx, "Nginx Server 3")]),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "EC2 Auto Scaling Group", [(EC2, "EC2 Web Server 1"), (EC2, "EC2 Web Server 2"), (EC2, "EC2 Web Server 3")]),
                (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Virtual Machine Scale Set", [(VirtualMachine, "VM Web Server 1"), (VirtualMachine, "VM Web Server 2"), (VirtualMachine, "VM Web Server 3")]),
                  (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "Application Server": {
        "description": "Hosts application logic (e.g., Java apps) with load balancing, multiple app servers, and storage for data.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "Application Server Cluster", [(Nginx, "Tomcat Server 1"), (Nginx, "Tomcat Server 2"), (Nginx, "Tomcat Server 3")]),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "EC2 Auto Scaling Group", [(EC2, "EC2 Tomcat Server 1"), (EC2, "EC2 Tomcat Server 2"), (EC2, "EC2 Tomcat Server 3")]),
                (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Virtual Machine Scale Set", [(VirtualMachine, "VM Tomcat Server 1"), (VirtualMachine, "VM Tomcat Server 2"), (VirtualMachine, "VM Tomcat Server 3")]),
                  (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "Container Orchestration": {
        "description": "Manages containerized applications with orchestration, ensuring scalability and availability across nodes.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "Kubernetes Cluster", [(Kubernetes, "Master Node"), (Kubernetes, "Worker Node 1"), (Kubernetes, "Worker Node 2")]),
                   (NetworkFileSystem, "Network File System Storage"), (Prometheus, "Monitoring Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "Elastic Kubernetes Service Cluster", [(ElasticKubernetesService, "Control Plane"), (EC2, "EC2 Worker Node 1"), (EC2, "EC2 Worker Node 2")]),
                (ElasticFileSystem, "Elastic File System"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Azure Kubernetes Service Cluster", [(AzureKubernetesService, "Control Plane"), (VirtualMachine, "VM Worker Node 1"), (VirtualMachine, "VM Worker Node 2")]),
                  (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "Virtual Machines": {
        "description": "Runs virtualized compute instances for general-purpose workloads with storage and monitoring.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "Virtual Machine Cluster", [(Nginx, "VM Server 1"), (Nginx, "VM Server 2"), (Nginx, "VM Server 3")]),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "EC2 Instance Group", [(EC2, "EC2 VM Server 1"), (EC2, "EC2 VM Server 2"), (EC2, "EC2 VM Server 3")]),
                (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Virtual Machine Cluster", [(VirtualMachine, "VM Server 1"), (VirtualMachine, "VM Server 2"), (VirtualMachine, "VM Server 3")]),
                  (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "Serverless Functions": {
        "description": "Executes code in response to events without managing servers, with storage for outputs and monitoring.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   (Nginx, "Serverless Proxy Server"), (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (APIGateway, "API Gateway"),
                (Lambda, "Lambda Functions"), (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (ApplicationGateway, "Application Gateway"),
                  (Functions, "Azure Functions"), (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "CI/CD Pipeline": {
        "description": "Automates code integration and deployment with a pipeline server, repository, and artifact storage.",
        "onprem": [(Users, "Clients"), (Jenkins, "Jenkins Server"), (Git, "Git Repository Server"),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (EC2, "CodePipeline Server"),
                (SimpleStorageService, "Simple Storage Service Artifacts"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (VirtualMachine, "DevOps Agent Server"),
                  (BlobStorage, "Blob Storage Artifacts"), (VirtualMachine, "Log Analytics Server")]
    },
    "Batch Processing System": {
        "description": "Processes large data batches with a scheduler, metadata storage, and output storage.",
        "onprem": [(Users, "Clients"), (Nginx, "Airflow Scheduler Server"), (Postgresql, "Metadata Database Server"),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (EC2, "Airflow Instance"),
                (RelationalDatabaseService, "Metadata Database"), (SimpleStorageService, "Simple Storage Service Output"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (VirtualMachine, "Airflow VM"),
                  (AzureDatabaseForPostgreSQL, "Metadata Database"), (BlobStorage, "Blob Storage Output"), (VirtualMachine, "Log Analytics Server")]
    },
    "API Gateway": {
        "description": "Routes and manages API requests to backend services with load balancing and storage.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   (Nginx, "API Gateway Server"), (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (APIGateway, "API Gateway"),
                (EC2, "Backend Server"), (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (ApplicationGateway, "Application Gateway"),
                  (VirtualMachine, "Backend Server"), (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "Load Balancer": {
        "description": "Distributes network traffic across multiple servers for high availability and performance.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "Web Server Cluster", [(Nginx, "Web Server 1"), (Nginx, "Web Server 2")]), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "EC2 Instances", [(EC2, "Web Server 1"), (EC2, "Web Server 2")]), (SimpleStorageService, "Simple Storage Service Bucket")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Virtual Machines", [(VirtualMachine, "Web Server 1"), (VirtualMachine, "Web Server 2")]), (BlobStorage, "Blob Storage")]
    },
    "Reverse Proxy": {
        "description": "Forwards client requests to backend servers, providing security and load balancing.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Nginx, "Reverse Proxy Server"),
                   ("Cluster", "Backend Cluster", [(Nginx, "Backend Server 1"), (Nginx, "Backend Server 2")]), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticLoadBalancer, "Elastic Load Balancer"),
                ("Cluster", "EC2 Instances", [(EC2, "Backend Server 1"), (EC2, "Backend Server 2")]), (SimpleStorageService, "Simple Storage Service Bucket")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (AzureLoadBalancer, "Azure Load Balancer"),
                  ("Cluster", "Virtual Machines", [(VirtualMachine, "Backend Server 1"), (VirtualMachine, "Backend Server 2")]), (BlobStorage, "Blob Storage")]
    },
    "Relational Database": {
        "description": "Stores structured data with a primary server for writes and replicas for reads, including backups and monitoring.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "PostgreSQL Cluster", [(Postgresql, "Primary Server"), (Postgresql, "Replica Server 1"), (Postgresql, "Replica Server 2")]),
                   (NetworkFileSystem, "Network File System Storage"), (NetworkFileSystem, "Backup Server")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"),
                ("Cluster", "Relational Database Service Cluster", [(RelationalDatabaseService, "Primary Instance"), (RelationalDatabaseService, "Read Replica 1"), (RelationalDatabaseService, "Read Replica 2")]),
                (SimpleStorageService, "Simple Storage Service Bucket"), (Cloudwatch, "CloudWatch Monitoring")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"),
                  ("Cluster", "Azure Database for PostgreSQL Cluster", [(AzureDatabaseForPostgreSQL, "Primary Server"), (AzureDatabaseForPostgreSQL, "Read Replica 1"), (AzureDatabaseForPostgreSQL, "Read Replica 2")]),
                  (BlobStorage, "Blob Storage"), (VirtualMachine, "Log Analytics Server")]
    },
    "NoSQL Database": {
        "description": "Manages unstructured or semi-structured data with flexible schemas and replication.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Haproxy, "HAProxy Load Balancer"),
                   ("Cluster", "MongoDB Cluster", [(Mongodb, "Primary Server"), (Mongodb, "Replica Server 1")]), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (Dynamodb, "DynamoDB Service"), (SimpleStorageService, "Simple Storage Service Backups")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (CosmosDb, "Cosmos DB Service"), (BlobStorage, "Blob Storage Backups")]
    },
    "Data Warehouse": {
        "description": "Stores and analyzes large volumes of historical data for reporting and analytics.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Postgresql, "Data Warehouse Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (Redshift, "Redshift Service"), (SimpleStorageService, "Simple Storage Service Storage")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (DataLakeStorage, "Data Lake Analytics Service"), (BlobStorage, "Blob Storage")]
    },
    "Data Lake": {
        "description": "Centralizes raw data storage for analytics with scalable file systems.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Glusterfs, "Data Lake Storage"), (NetworkFileSystem, "Network File System Backup")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (SimpleStorageService, "Simple Storage Service Data Lake"), (ElasticFileSystem, "Elastic File System Backup")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (DataLakeStorage, "Azure Data Lake Storage"), (BlobStorage, "Blob Storage Backup")]
    },
    "In-Memory Cache": {
        "description": "Provides fast data access with in-memory storage for caching frequently used data.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Redis, "Redis Cache Server"), (NetworkFileSystem, "Network File System Backups")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (Redis, "ElastiCache Service"), (SimpleStorageService, "Simple Storage Service Backups")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (Redis, "Azure Cache Service"), (BlobStorage, "Blob Storage Backups")]
    },
    "Object Storage": {
        "description": "Stores unstructured data as objects with scalable, distributed access.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (NetworkFileSystem, "MinIO Server"), (Glusterfs, "Backend Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (SimpleStorageService, "Simple Storage Service Bucket"), (ElasticFileSystem, "Elastic File System Backup")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (BlobStorage, "Blob Storage"), (DataLakeStorage, "Data Lake Backup")]
    },
    "Block Storage": {
        "description": "Provides raw block-level storage for high-performance applications.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (NetworkFileSystem, "iSCSI Storage Server"), (Glusterfs, "Backend Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (EC2, "EC2 Instance"), (SimpleStorageService, "Simple Storage Service Block Volume")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (VirtualMachine, "VM Instance"), (BlobStorage, "Disk Storage")]
    },
    "File Storage": {
        "description": "Offers shared file system storage accessible by multiple servers or clients.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (NetworkFileSystem, "Network File System Server"), (Glusterfs, "Storage Backend")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (ElasticFileSystem, "Elastic File System"), (SimpleStorageService, "Simple Storage Service Backup")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (BlobStorage, "Azure Files Storage"), (DataLakeStorage, "Backup Storage")]
    },
    "Backup and Archival": {
        "description": "Manages data backups and long-term archival storage for disaster recovery.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (NetworkFileSystem, "Backup Server"), (Glusterfs, "Archival Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (SimpleStorageService, "Simple Storage Service Backup"), (ElasticFileSystem, "Archival Storage")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (BlobStorage, "Blob Backup Storage"), (DataLakeStorage, "Archival Storage")]
    },
    "Streaming Platform": {
        "description": "Processes real-time data streams with brokers and persistent storage.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (Nginx, "Kafka Broker Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS"), (EC2, "Kafka Instance"), (SimpleStorageService, "Simple Storage Service Storage")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones"), (VirtualMachine, "Kafka VM"), (BlobStorage, "Blob Storage")]
    },
    "DNS Service": {
        "description": "Resolves domain names to IP addresses for network accessibility.",
        "onprem": [(Users, "Clients"), (Coredns, "CoreDNS Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (Route53, "Route 53 DNS Service"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (AzureDNSZones, "Azure DNS Zones Service"), (BlobStorage, "Blob Storage Logs")]
    },
    "DHCP Server": {
        "description": "Assigns IP addresses dynamically to devices on a network.",
        "onprem": [(Users, "Clients"), (Nginx, "DHCP Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "DHCP Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "DHCP VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "VPN Gateway": {
        "description": "Secures remote access to a network via encrypted tunnels.",
        "onprem": [(Users, "Clients"), (Nginx, "OpenVPN Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "VPN Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "VPN VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Firewall": {
        "description": "Protects networks by filtering traffic based on security rules.",
        "onprem": [(Users, "Clients"), (Nginx, "pfSense Firewall Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "Firewall Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Firewall VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Intrusion Detection System": {
        "description": "Monitors network traffic for suspicious activity and alerts administrators.",
        "onprem": [(Users, "Clients"), (Nginx, "Snort IDS Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "IDS Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "IDS VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Content Delivery Network": {
        "description": "Distributes content globally for faster delivery using edge servers.",
        "onprem": [(Users, "Clients"), (Nginx, "CDN Proxy Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (CloudFront, "CloudFront Service"), (SimpleStorageService, "Simple Storage Service Content")],
        "azure": [(Users, "Clients"), (ApplicationGateway, "CDN Gateway"), (BlobStorage, "Blob Storage Content")]
    },
    "Network Load Balancer": {
        "description": "Distributes network traffic at the transport layer for high performance.",
        "onprem": [(Users, "Clients"), (Haproxy, "HAProxy Network Load Balancer"), (Nginx, "Backend Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (ElasticLoadBalancer, "Network Load Balancer"), (EC2, "Backend Server"), (SimpleStorageService, "Simple Storage Service Bucket")],
        "azure": [(Users, "Clients"), (AzureLoadBalancer, "Network Load Balancer"), (VirtualMachine, "Backend Server"), (BlobStorage, "Blob Storage")]
    },
    "Proxy Server": {
        "description": "Intermediates client requests to external services for caching and security.",
        "onprem": [(Users, "Clients"), (Nginx, "Squid Proxy Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "Proxy Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Proxy VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "IP Address Management": {
        "description": "Manages IP address allocation and tracking within a network.",
        "onprem": [(Users, "Clients"), (Nginx, "IPAM Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "IPAM Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "IPAM VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Zero Trust Network Access": {
        "description": "Enforces strict identity verification for network access, regardless of location.",
        "onprem": [(Users, "Clients"), (Nginx, "ZTNA Gateway Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "ZTNA Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "ZTNA VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Identity Provider": {
        "description": "Manages user authentication and identity services for secure access.",
        "onprem": [(Users, "Clients"), (Nginx, "Keycloak Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (EC2, "IdP Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "IdP VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Multi-Factor Authentication Service": {
        "description": "Enhances security with additional authentication factors beyond passwords.",
        "onprem": [(Users, "Clients"), (Nginx, "MFA Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "MFA Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "MFA VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Certificate Authority": {
        "description": "Issues and manages digital certificates for secure communication.",
        "onprem": [(Users, "Clients"), (Nginx, "CA Server"), (NetworkFileSystem, "Network File System Certificates")],
        "aws": [(Users, "Clients"), (EC2, "CA Instance"), (SimpleStorageService, "Simple Storage Service Certificates")],
        "azure": [(Users, "Clients"), (VirtualMachine, "CA VM"), (BlobStorage, "Blob Storage Certificates")]
    },
    "SIEM Platform": {
        "description": "Collects and analyzes security events for threat detection and response.",
        "onprem": [(Users, "Clients"), (Elasticsearch, "Splunk Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "SIEM Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "SIEM VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Secret Manager": {
        "description": "Securely stores and manages sensitive credentials and secrets.",
        "onprem": [(Users, "Clients"), (Vault, "Vault Server"), (NetworkFileSystem, "Network File System Backups")],
        "aws": [(Users, "Clients"), (SecretsManager, "Secrets Manager Service"), (SimpleStorageService, "Simple Storage Service Backups")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Vault VM"), (BlobStorage, "Blob Storage Backups")]
    },
    "Endpoint Detection and Response": {
        "description": "Monitors endpoints for security threats and responds to incidents.",
        "onprem": [(Users, "Clients"), (Nginx, "EDR Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "EDR Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "EDR VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Web Application Firewall": {
        "description": "Protects web applications by filtering and monitoring HTTP traffic.",
        "onprem": [(Users, "Clients"), (Nginx, "WAF Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (ElasticLoadBalancer, "WAF Load Balancer"), (EC2, "Backend Server"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (ApplicationGateway, "WAF Gateway"), (VirtualMachine, "Backend Server"), (BlobStorage, "Blob Storage Logs")]
    },
    "Monitoring System": {
        "description": "Tracks system performance and health with metrics collection and visualization.",
        "onprem": [(Users, "Clients"), (Prometheus, "Prometheus Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Cloudwatch, "CloudWatch Monitoring Service"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Monitoring VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Logging Stack": {
        "description": "Collects, stores, and analyzes logs from systems and applications.",
        "onprem": [(Users, "Clients"), (Elasticsearch, "ELK Stack Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (Cloudwatch, "CloudWatch Logs Service"), (SimpleStorageService, "Simple Storage Service Storage")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Logging VM"), (BlobStorage, "Blob Storage")]
    },
    "Configuration Management": {
        "description": "Automates configuration and management of infrastructure components.",
        "onprem": [(Users, "Clients"), (Nginx, "Ansible Server"), (NetworkFileSystem, "Network File System Configs")],
        "aws": [(Users, "Clients"), (EC2, "Config Instance"), (SimpleStorageService, "Simple Storage Service Configs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Config VM"), (BlobStorage, "Blob Storage Configs")]
    },
    "Infrastructure as Code": {
        "description": "Manages infrastructure through code with versioning and automation.",
        "onprem": [(Users, "Clients"), (Nginx, "Terraform Server"), (NetworkFileSystem, "Network File System State Files")],
        "aws": [(Users, "Clients"), (EC2, "Terraform Instance"), (SimpleStorageService, "Simple Storage Service State Files")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Terraform VM"), (BlobStorage, "Blob Storage State Files")]
    },
    "IT Service Management": {
        "description": "Manages IT services and incidents with a centralized platform.",
        "onprem": [(Users, "Clients"), (Nginx, "ServiceNow Server"), (NetworkFileSystem, "Network File System Data")],
        "aws": [(Users, "Clients"), (EC2, "ITSM Instance"), (SimpleStorageService, "Simple Storage Service Data")],
        "azure": [(Users, "Clients"), (VirtualMachine, "ITSM VM"), (BlobStorage, "Blob Storage Data")]
    },
    "Alerting System": {
        "description": "Sends notifications based on system metrics and thresholds.",
        "onprem": [(Users, "Clients"), (Prometheus, "Alertmanager Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (Cloudwatch, "CloudWatch Alerts Service"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Alerting VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Metrics Dashboard": {
        "description": "Visualizes system metrics for performance monitoring.",
        "onprem": [(Users, "Clients"), (Grafana, "Grafana Server"), (NetworkFileSystem, "Network File System Data")],
        "aws": [(Users, "Clients"), (Cloudwatch, "CloudWatch Dashboards Service"), (SimpleStorageService, "Simple Storage Service Data")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Grafana VM"), (BlobStorage, "Blob Storage Data")]
    },
    "Git Repository Hosting": {
        "description": "Hosts version control repositories for source code management.",
        "onprem": [(Users, "Clients"), (Git, "Gitea Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (EC2, "CodeCommit Instance"), (SimpleStorageService, "Simple Storage Service Backups")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Azure Repos VM"), (BlobStorage, "Blob Storage Backups")]
    },
    "Artifact Repository": {
        "description": "Stores and manages build artifacts and dependencies.",
        "onprem": [(Users, "Clients"), (Nginx, "Nexus Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (EC2, "Artifact Instance"), (SimpleStorageService, "Simple Storage Service Storage")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Artifact VM"), (BlobStorage, "Blob Storage")]
    },
    "Local Development Environment": {
        "description": "Provides isolated environments for local development and testing.",
        "onprem": [(Users, "Clients"), (Vagrant, "Vagrant Server"), (NetworkFileSystem, "Network File System Storage")],
        "aws": [(Users, "Clients"), (EC2, "Dev Instance"), (SimpleStorageService, "Simple Storage Service Storage")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Dev VM"), (BlobStorage, "Blob Storage")]
    },
    "Code Quality Analysis": {
        "description": "Analyzes code for quality, security, and maintainability.",
        "onprem": [(Users, "Clients"), (Nginx, "SonarQube Server"), (NetworkFileSystem, "Network File System Reports")],
        "aws": [(Users, "Clients"), (EC2, "Quality Instance"), (SimpleStorageService, "Simple Storage Service Reports")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Quality VM"), (BlobStorage, "Blob Storage Reports")]
    },
    "ChatOps Integration": {
        "description": "Integrates chat tools with operations for collaboration and automation.",
        "onprem": [(Users, "Clients"), (Nginx, "Mattermost Server"), (NetworkFileSystem, "Network File System Logs")],
        "aws": [(Users, "Clients"), (EC2, "ChatOps Instance"), (SimpleStorageService, "Simple Storage Service Logs")],
        "azure": [(Users, "Clients"), (VirtualMachine, "ChatOps VM"), (BlobStorage, "Blob Storage Logs")]
    },
    "Developer Portal/Service Catalog": {
        "description": "Provides a centralized portal for developer tools and service discovery.",
        "onprem": [(Users, "Clients"), (Nginx, "Backstage Server"), (NetworkFileSystem, "Network File System Data")],
        "aws": [(Users, "Clients"), (EC2, "Portal Instance"), (SimpleStorageService, "Simple Storage Service Data")],
        "azure": [(Users, "Clients"), (VirtualMachine, "Portal VM"), (BlobStorage, "Blob Storage Data")]
    }
}

# Load available deployments
deployment_names = sorted([f.replace("_onprem.png", "").replace("_aws.png", "").replace("_azure.png", "")
                           for f in os.listdir("arch") if f.endswith(".png")])
deployment_names = sorted(set(deployment_names))  # unique names

env_map = {
    "On-Premises": "onprem",
    "AWS": "aws",
    "Azure": "azure"
}

# st.set_page_config(layout="wide", initial_sidebar_state="expanded", page_title="Systems Architecture")

st.title("SEAS-8405: Simple Architecture Explorer")

# Let the user pick a deployment (e.g., "web_service") from the PNG files
selected_deployment = st.sidebar.selectbox("Select a Deployment", deployment_names)

# Let the user pick an environment (onprem, aws, azure)
selected_env_label = st.sidebar.radio("Choose an Environment", list(env_map.keys()), horizontal=True)
selected_env = env_map[selected_env_label]

# Construct the PNG filename
image_filename = f"arch/{selected_deployment.lower()}_{selected_env}.png"

# --- NEW CODE TO SHOW THE DESCRIPTION ---
# We need to map "web_service" back to "Web Service" (the dictionary key).
# If your dictionary keys match the result of .title().replace("_"," "),
# this will work. If you have special characters like "/", you might need extra logic.
def map_filename_to_dict_key(filename: str) -> str:
    return filename.replace("_", " ").title()

dict_key = map_filename_to_dict_key(selected_deployment)

# Display the description if it exists
if dict_key in deployments:
    st.sidebar.info(deployments[dict_key]["description"])
else:
    st.sidebar.warning(f"No description found in deployments for '{dict_key}'.")

# Show the corresponding diagram if it exists
if os.path.exists(image_filename):
    st.image(image_filename,
             caption=f"{dict_key} - {selected_env_label}",
             use_column_width=True)
else:
    st.warning(f"Diagram not found for {dict_key} in {image_filename}.")