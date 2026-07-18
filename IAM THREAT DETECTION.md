# 🔍 IAM Threat Detection & Monitoring Handbook

## ☁️ CloudTrail Events to Monitor for IAM
* **ConsoleLogin:** Alert on new IP/country, login without MFA, root login, or failed then success pattern.
* **CreateUser:** Alert on any creation not from approved provisioning automation.
* **CreateAccessKey:** Alert on creation for root account (critical), any creation outside rotation process.
* **AttachUserPolicy / AttachRolePolicy:** Alert on `AdministratorAccess` or `PowerUserAccess` attached by non-admin user.
* **PutUserPolicy / PutRolePolicy:** Alert on inline policy with wildcard (`*`) permissions added.
* **CreateRole / UpdateAssumeRolePolicy:** Alert on trust policy with `Principal:*` or unknown account IDs.
* **AssumeRole:** Alert on assumption from unexpected IP/account/service, high-privilege role at unusual time, chained AssumeRole calls.
* **AddUserToGroup:** Alert on user added to admin or high-privilege groups.
* **GetAccountAuthorizationDetails:** Alert on called by non-approved automation. Classic enumeration.
* **ListUsers / ListRoles / ListPolicies:** Alert on burst of `List*` from unfamiliar identity.
* **UpdateLoginProfile:** Alert on password changed for user who did not initiate it.

---

## 🎯 Attack Patterns to Detect in SIEM
* **Pattern 1 - Credential Compromise:** `ConsoleLogin` success from new IP then `GetAccountAuthorizationDetails` then `CreateUser` or `CreateAccessKey` within minutes.
* **Pattern 2 - Privilege Escalation:** Low-privilege user calls `AttachUserPolicy` with `AdministratorAccess` as the policyArn.
* **Pattern 3 - Backdoor Key Creation:** `CreateAccessKey` outside business hours or not from approved automation.
* **Pattern 4 - Role Chaining Lateral Movement:** `AssumeRole` from EC2 instance then `AssumeRole` again to different higher-privilege role.
* **Pattern 5 - IAM Reconnaissance:** 10+ different IAM List/Describe/Get calls within 5 minutes.
* **Pattern 6 - Root Usage:** Any API call with `userIdentity.type=Root`.

---

## 📊 Splunk SPL Queries for IAM Detection

**Root account usage:**
```spl
index=cloudtrail userIdentity.type=Root | table _time, eventName, sourceIPAddress
```

**New IAM user creation:**
```spl
index=cloudtrail eventName=CreateUser | table _time, requestParameters.userName, userIdentity.arn, sourceIPAddress
```

**Admin policy attached by non-admin:**
```spl
index=cloudtrail eventName IN (AttachUserPolicy,AttachRolePolicy) requestParameters.policyArn=*AdministratorAccess* | table _time, userIdentity.arn, sourceIPAddress
```

**IAM enumeration detection:**
```spl
index=cloudtrail eventName IN (ListUsers,ListRoles,ListPolicies,GetAccountAuthorizationDetails) | stats count dc(eventName) as unique_calls by userIdentity.arn, sourceIPAddress | where count > 5
```

**New access key creation:**
```spl
index=cloudtrail eventName=CreateAccessKey | table _time, requestParameters.userName, userIdentity.arn, sourceIPAddress
```

**CloudTrail disabled:**
```spl
index=cloudtrail eventName IN (StopLogging,DeleteTrail,UpdateTrail) | table _time, userIdentity.arn, sourceIPAddress
```

---

## 🛡️ GuardDuty IAM Finding Types to Know
* **UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B:** Console login from unusual location.
* **UnauthorizedAccess:IAMUser/MaliciousIPCaller:** API call from known malicious IP.
* **Recon:IAMUser/MaliciousIPCaller:** Reconnaissance calls from known malicious IP.
* **Policy:IAMUser/RootCredentialUsage:** Root account used.
* **Stealth:IAMUser/CloudTrailLoggingDisabled:** CloudTrail was disabled.
* **UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS:** IMDS/SSRF credential theft.
* **PenTest:IAMUser/KaliLinux:** API calls from Kali Linux user-agent.

---

## ⚙️ AWS Config Rules for IAM
* `iam-root-access-key-check`
* `root-account-mfa-enabled`
* `iam-user-mfa-enabled`
* `access-keys-rotated` (90 days)
* `iam-password-policy`
* `iam-no-inline-policy-check`
* `iam-user-no-policies-check` (use groups/roles not direct user attachment)
