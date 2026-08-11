# 🛡️ AWS Automated Threat Mitigation & Honeypot Defense Engine

An event-driven, serverless cloud security architecture that automatically detects brute-force/unauthorized access attempts on a decoy Honeypot server and injects real-time **Deny Rules** at the VPC Subnet boundary using **AWS Lambda** and **Network Access Control Lists (NACL)**.

---

## 🎯 Problem Statement & Business Impact

* **High Operational Overhead:** Manual SOC analyst intervention to parse logs and update firewalls takes 10 to 30 minutes per incident.
* **Server Resource Exhaustion:** Continuous SSH/Port brute-force scanning consumes critical CPU cycles, memory, and cloud bandwidth.
* **Solution Impact:** Reduces Mean Time to Respond (**MTTR**) from minutes to **< 2 seconds** via fully automated, serverless event-driven infrastructure without human intervention.

---

## 🏗️ System Architecture

<img width="1024" height="627" alt="01_Architecture_Diagram png" src="https://github.com/user-attachments/assets/e02ac400-c879-4ffc-93b6-126f131fb5b3" />


```text
+---------------------------------------------------------------------------------+
|                                 ATTACK PHASE                                    |
+---------------------------------------------------------------------------------+
                                       │
                         [ Attacker / Botnet IP: 1.2.3.4 ]
                                       │
                                       ▼ (SSH / Brute-Force Request)
                       ┌───────────────────────────────┐
                       │  EC2 Honeypot (Port 22 Decoy) │
                       └───────────────┬───────────────┘
                                       │
                                       │ (Security Event Triggered)
                                       ▼
+---------------------------------------------------------------------------------+
|                             DETECTION & ROUTING                                 |
+---------------------------------------------------------------------------------+
                                       │
                         ┌───────────────────────────┐
                         │      AWS EventBridge      │
                         │  (Event: custom.honeypot) │
                         └─────────────┬─────────────┘
                                       │
                                       │ (Triggers Lambda Payload)
                                       ▼
+---------------------------------------------------------------------------------+
|                             AUTOMATED EXECUTION                                 |
+---------------------------------------------------------------------------------+
                                       │
                         ┌───────────────────────────┐
                         │     AWS Lambda Engine     │
                         │   (Python + Boto3 SDK)    │
                         └─────────────┬─────────────┘
                                       │
                                       │ 1. Extracts IP: "1.2.3.4"
                                       │ 2. Calls EC2 API to update NACL
                                       ▼
+---------------------------------------------------------------------------------+
|                        ENFORCEMENT (VPC SUBNET GATE)                            |
+---------------------------------------------------------------------------------+
                                       │
                       ┌───────────────────────────────┐
                       │   VPC Network ACL (NACL)      │
                       │  acl-053b9829cddbd997b        │
                       ├───────────────────────────────┤
                       │  Rule 50  : 1.2.3.4/32  DENY ◄─── (INJECTED BY LAMBDA)
                       │  Rule 100 : 0.0.0.0/0   ALLOW
                       └───────────────┬───────────────┘
                                       │
                                       ▼
            [ TRAFFIC FROM 1.2.3.4 DROPPED AT SUBNET BOUNDARY ]

```

## ⚡ How It Works Step-by-Step

1. **Reconnaissance & Trigger:** An attacker attempts an unauthorized login/scan on the Honeypot EC2 instance.
2. **Event Dispatch:** AWS EventBridge catches the security event telemetry (`custom.honeypot` schema).
3. **Payload Processing:** AWS Lambda parses the incoming JSON payload and dynamically extracts the attacker's source IP address.
4. **Subnet-Level Enforcement:** Lambda calls the EC2 API via `boto3` and inserts a high-priority entry (**Rule 50: DENY**) into the target Network ACL.
5. **Mitigation:** The malicious IP is instantly dropped at the Subnet boundary before reaching any compute resources.

---

## 🛠️ Tech Stack & Services Used

* **Cloud Provider:** Amazon Web Services (AWS)
* **Compute / Decoy:** AWS EC2 (Amazon Linux 2023)
* **Event Router:** AWS EventBridge
* **Serverless Automation:** AWS Lambda (Python 3.12, Boto3 SDK)
* **Network Security:** AWS VPC Network Access Control Lists (NACL)

## 🐍 AWS Lambda Core Execution Logic

```
import json
import boto3

ec2 = boto3.client('ec2')

# Target VPC Network ACL ID
NACL_ID = 'acl-053b9829cddbd997b'

def lambda_handler(event, context):
    try:
        # Extract Attacker IP from event payload
        attacker_ip = event.get('detail', {}).get('attacker_ip')
        
        if not attacker_ip:
            return {'statusCode': 400, 'body': 'No attacker IP found in event.'}
            
        print(f"[ALERT] Malicious activity detected from IP: {attacker_ip}")
        
        # Inject High-Priority Rule (Rule 50) to block incoming traffic
        response = ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=50,
            Protocol='-1',       # Block all protocols
            RuleAction='deny',   # Deny Traffic
            Egress=False,        # Inbound Rule
            CidrBlock=f"{attacker_ip}/32" # Single IP Specificity
        )
        
        print(f"[SUCCESS] Successfully blocked IP {attacker_ip} in NACL {NACL_ID}")
        return {'statusCode': 200, 'body': f"IP {attacker_ip} blocked successfully!"}
        
    except Exception as e:
        print(f"[ERROR] Failed to block IP: {str(e)}")
        raise e

```

## 📸 Verification & Proof of Concept

### Live Threat Block in Network ACL (Rule 50 Injected)
As verified in the VPC Console, the Lambda execution dynamically prepended **Rule 50** with a `DENY` action for `1.2.3.4/32` before the default `Rule 100 ALLOW` rule.

---

## 🛡️ Production & Enterprise Scale Considerations

* **Rate-Limiting / Thresholds:** In production, rules trigger after a specific threshold (e.g., > 5 failed logins within 10s) using CloudWatch Metric Filters.
* **Temporary Blocking (TTL):** Implement dynamic rule removal via scheduled Step Functions to automatically expire bans after 1 hour.
* **Allowlisting:** Maintain an AWS SSM Parameter Store list of whitelisted admin IPs to prevent accidental lockouts.

## 📸 Verification & Screenshots

<div align="center">
  <img src="https://github.com/user-attachments/assets/93e6ecff-61bd-45f6-9657-a3023cf5953f" width="48%" alt="Lambda Code & Trigger" />
  <img src="https://github.com/user-attachments/assets/f4873033-4c2e-445c-a4b1-4a16fedd7aca" width="48%" alt="EventBridge Rule" />
</div>

<br />

<div align="center">
  <img src="https://github.com/user-attachments/assets/a9d16575-e657-4da9-bd28-849bbf9acfbf" width="80%" alt="NACL Blocked IP" />
</div>
