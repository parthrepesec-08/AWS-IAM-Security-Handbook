## IAM Attack Surfaces - What Can Go Wrong

Overprivileged IAM identities - user or role with AdministratorAccess or wildcard (*) permissions. Most common IAM vulnerability. If
compromised, attacker has full account control.

Exposed access keys - keys hardcoded in code, committed to GitHub, stored in S3 or Lambda env vars. Automated bots scan GitHub 24/7.
Exposed key is typically abused within minutes.

No MFA on root account or console users - root without MFA is the single highest-risk config. Root compromise = unlimited access to
everything including billing and account deletion.

Privilege escalation paths - user with iam:AttachUserPolicy can attach AdministratorAccess to self. 40+ known IAM privilege escalation
techniques exist. Tools like PMapper enumerate these automatically.

Cross-account role abuse - roles with trust policy allowing Principal:* (anyone can assume), or trust to unknown external account IDs.
Long-lived credentials - access keys not rotated for months/years. Longer a key exists, higher probability it has been exposed somewhere.
Permission creep - identities accumulatepermissions over time, old ones never removed. Attacker who compromises such identity has far
broader access than expected.

Weak password policy - no minimum length, no MFA requirement, no expiry. Enables brute force and credential stuffing on the console
login.

No CloudTrail - attacker operates freely with no audit log of their actions.
IAM MITRE ATT&CK; Techniques


# T1078.004 - Valid Accounts: Cloud Accounts - use stolen credentials to authenticate.
T1098.001 - Additional Cloud Credentials - create new access keys for persistence.
T1136.003 - Create Cloud Account - create new IAM user as backdoor.
T1548 - Abuse Elevation: Attach Policy to Self - attach AdministratorAccess to own account.
T1550.001 - Use Alternate Auth: Application Access Token - steal and reuse STS temp credentials.
T1552.005 - Unsecured Credentials: Cloud Instance Metadata API - SSRF to steal EC2 instance role creds.
T1580 - Cloud Infrastructure Discovery via IAM Enumeration - ListUsers, ListRoles, GetAccountAuthorizationDetails.


# IAM Controls to Apply (Threat Modeling Output)
Enforce least privilege: specific actions on specific resources only. No wildcards unless justified.
Enable MFA: root account (mandatory), all console users, all users with sensitive IAM permissions.
Use roles not users for applications and services - no long-lived access keys in code.
Mandatory access key rotation: Config rule access-keys-rotated, alert on keys older than 90 days.
Enable IAM Access Analyzer in every account and region.
Use permission boundaries on all IAM users created by developers or automation.
SCP at Organizations: deny disabling CloudTrail, deny root access keys, deny IAM users without MFA.
Strong password policy: minimum 14 characters, complexity required, 90-day expiry, no reuse of last 24.
Config rule iam-root-access-key-check: alert if root has active access keys.
