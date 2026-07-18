![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Splunk](https://img.shields.io/badge/splunk-%23000000.svg?style=for-the-badge&logo=splunk&logoColor=white)
![CyberSecurity](https://img.shields.io/badge/Security-Blue_Team-blue?style=for-the-badge)
# 🔐 AWS IAM Security Handbook

This repository is a comprehensive, practical guide designed for Cloud Security professionals, SOC Analysts, and anyone looking to secure AWS Identity and Access Management (IAM) infrastructure. It breaks down complex IAM vulnerabilities, detection mechanisms, and step-by-step incident response procedures.

## 📂 Repository Structure

This handbook is divided into three critical phases of cloud security:

### 🛡️ 1. [IAM Threat Modeling](./IAM%20THREAT%20MODELING.md)
Understand how attackers target AWS environments.
* Common attack surfaces and misconfigurations.
* Privilege escalation paths and cross-account role abuse.
* IAM vulnerabilities mapped to the MITRE ATT&CK framework.

### 🔍 2. [IAM Threat Detection](./IAM%20THREAT%20DETECTION.md)
Learn how to spot malicious activity in real-time.
* Critical CloudTrail events to monitor.
* Ready-to-use **Splunk SPL Queries** for IAM detection.
* Key Amazon GuardDuty finding types and AWS Config rules.

### 🚨 3. [IAM Incident Response](./IAM%20INCIDENT%20RESPONSE.md)
A complete runbook for handling confirmed IAM compromises.
* Step-by-step containment strategies for compromised Users, Roles, and Root accounts.
* Investigation tactics using CloudTrail and AWS Detective.
* Eradication and safe recovery procedures.

## 🎯 Why This Matters
Identity is the true perimeter in the cloud. A single exposed access key, an overprivileged role, or a weak trust policy can lead to a complete account compromise within minutes. This handbook provides the actionable steps needed to model, detect, and respond to these exact threats efficiently.

---
*Built to help secure cloud environments through practical threat modeling and rapid response.*
