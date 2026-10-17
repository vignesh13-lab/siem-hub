---
title: Brute Force Login Attempts
mitre: T1110
data_source: index=demo_auth
severity: high
owner: SOC Detection Team
status: production
---

# Brute Force Login Attempts

## Description
Detects a single source with many failed logins against multiple accounts in a short window.

## SPL
```spl
index=demo_auth action=failure
| bin _time span=10m
| stats dc(user) as users, count as failures by _time, src
| where failures > 20 AND users > 3
```

## Tuning and false positives
Exclude vulnerability scanners and known VPN gateways using a lookup.

## Response
See [Account Compromise SOP](../sops/account-compromise.md).

## Raw file
`content/spl/brute_force_login.spl`
