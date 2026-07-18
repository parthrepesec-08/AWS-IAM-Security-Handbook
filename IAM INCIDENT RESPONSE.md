## IAM INCIDENT RESPONSE
*Step-by-step response when an IAM identity is confirmed compromised*

## 🛠️ 4.1 Preparation - Write This Before an Incident Happens
* **Pre-create QUARANTINE-DENY-ALL inline policy:** `Effect:Deny, Action:*, Resource:*`. Attach to any identity instantly during IR to block all API calls.
* **Document Authority:** Document exactly who has the authority to deactivate credentials during an incident.
* **Know the difference:** 
  * *Deactivate key:* Stops use, key still exists.
  * *Delete key:* Permanent removal.
  * *Disable IAM user:* Stops all access including console.
* **Set up automated response:** Create an EventBridge rule that triggers a Lambda function to auto-deactivate access keys when a GuardDuty finding severity is HIGH or CRITICAL.

---

## 🔍 4.2 Triage - Confirm the Incident
* **Which IAM identity?** User ARN, role ARN, or access key ID?
* **What API calls did this identity make** in the last 24-48 hours? (Run CloudTrail query).
* **Was new infrastructure created?** (`RunInstances`, `CreateBucket`, `CreateUser`?)
* **Was data accessed?** (`GetObject`, `GetSecretValue`, `DescribeDBInstances`?)
* **Is the attacker still active** right now?
* **Source IP geolocation?** Is it a known malicious IP or a Tor exit node?

---

## 🛑 4.3 Containment

### 👤 Compromised IAM User
* **Step 1:** Deactivate ALL access keys immediately.
* **Step 2:** Attach `QUARANTINE-DENY-ALL` inline policy to the user.
* **Step 3:** Revoke all active console sessions.
* **Step 4:** Disable the IAM user account completely.
* **Step 5:** Remove the user from all groups and remove any trust relationships.

### 🎭 Compromised IAM Role
* **Step 1:** Attach an inline deny policy with the condition `DateLessThan aws:TokenIssueTime:[compromise-timestamp]`. This invalidates all STS tokens issued before the compromise.
* **Step 2:** Isolate the resource using the role (e.g., block EC2 security group, disable Lambda trigger).
* **Step 3:** Remove the role from the resource or replace it with a clean, tightly-scoped role.

### 👑 Root Account Compromised
* **Step 1:** Change the root password immediately from a clean, trusted machine.
* **Step 2:** Re-enable/regenerate the root MFA device.
* **Step 3:** Delete any root access keys (Root should *never* have access keys).
* **Step 4:** Review all CloudTrail root events for the past 90 days.
* **Step 5:** Contact AWS Support immediately - they have additional tools for root compromise recovery.

---

## 🕵️ 4.4 Investigation - Full Scope Analysis

**Query ALL CloudTrail events by the compromised identity (from compromise to containment):**
```spl
index=cloudtrail userIdentity.arn="[compromised-arn]" earliest=-7d | table _time, eventName, requestParameters, sourceIPAddress | sort _time
```

* **Find all persistence created by the attacker:** New IAM users, new access keys, new roles, new policies attached, new Lambda functions, new EC2 instances.
* **Find all data accessed:** `GetObject` (S3), `GetSecretValue` (Secrets Manager), `GetParameter`, `DescribeDBInstances`.
* **Use AWS Detective:** Open Detective, find the compromised entity, and review the behavior graph (automatically shows all related activity and resources).
* **Determine root cause:** GitHub exposure? Phishing? SSRF? Insider threat? Brute force? *The root cause determines your eradication and prevention steps.*

---

## 🧹 4.5 Eradication - Remove All Attacker Presence
* **Delete** all attacker-created IAM users, roles, groups, and policies.
* **Revoke** all attacker-created access keys.
* **Remove** all backdoor policy attachments.
* **Reset** compromised user credentials with a new strong password and a new MFA device.
* **If GitHub key exposure:** Rotate ALL keys in the account (assume all code-stored keys are compromised), implement pre-commit hooks with `git-secrets` or `Gitleaks`.
* **If SSRF root cause:** Patch the vulnerable app, enforce IMDSv2 on all EC2 instances, and review all instance role permissions for least privilege.
* **Apply tighter IAM policies:** Use this incident to right-size overprivileged identities.

---

## 🔄 4.6 Recovery - Restore Normal Operations
* **Re-enable IAM user** only after new credentials and MFA are confirmed.
* **Remove** the `QUARANTINE-DENY-ALL` inline policy.
* **Reattach ONLY minimum required policies** - do NOT restore the previous overprivileged state.
* **Re-enable** CloudTrail and GuardDuty if they were disabled by the attacker.
* **Monitor** the recovered identity closely for 30 days with heightened alerting.
* **Verify** all other identities are clean (the compromised identity may have created backdoors in other services).

---

## 📝 4.7 Post-Incident - Document and Improve
* **Write IAM Incident Report:** Include timeline, root cause, what the attacker accessed, what was created/modified, containment actions, recovery steps, and cost impact.
* **Identify detection gaps:** Write a new SIEM rule or Config rule to catch this pattern earlier next time.
* **Update IAM IR Runbook** with lessons learned.
* **Implement prevention:** Add secret scanning, schedule IAM Access Analyzer, and use MFA SCPs (Service Control Policies).
* **Conduct IAM-wide audit:** Use this incident as a trigger to review ALL identities for excessive permissions, unused accounts, and unrotated keys.
<img width="1360" height="1600" alt="iam_incident_response_flow" src="https://github.com/user-attachments/assets/48d3e8fa-3471-497b-864e-8e8960ac9f1b" />
