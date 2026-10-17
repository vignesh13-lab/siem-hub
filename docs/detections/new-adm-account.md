---
title: New Admin Account Created
mitre: T1136
data_source: index=demo_windows
severity: medium
owner: SOC Detection Team
status: production
---

# New Admin Account Created

## Description
Alerts when a user is added to a privileged group.

## SPL
```spl
index=demo_windows EventCode=4728 OR EventCode=4732
| stats count by _time, user, Group_Name, src_user
```

## Tuning and false positives
Suppress approved change windows and provisioning service accounts.

## Response
See [Account Compromise SOP](../sops/account-compromise.md).

## Raw file
`content/spl/new_admin_account.spl`
