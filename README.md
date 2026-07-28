# aclcheck
A lightweight Active Directory ACL checker built with Impacket and ldap3. It can enumerate attack-relevant outbound permissions for a principal, list group memberships, or show trustees with rights over a specific target object. Although it does not aim to fully replicate BloodHound's effective permission analysis and therefore may not always match BloodHound's results in complex ACL scenarios, it is intended as a lightweight alternative for small environments and situations where you cannot or do not want to use BloodHound.

## Requirements

- Python 3
- Impacket 0.13.x
- ldap3

## Usage examples

### Outbound rights for a principal
```
python3 aclcheck.py domain.local/user -principal targetuser -k -no-pass -dc-host dc01.domain.local
```
Sample output:
```
python aclcheck_light_v5.py -dc-ip 10.10.10.10 -principal alice domain.local/alice:'Password' -use-ldaps

Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Resolved 2 group SID(s), including the primary group
[*] Principal: alice
[*] Principal DN: CN=Alice A,CN=Users,DC=domain,DC=local
[*] Principal SID: S-1-5-21-123456789-0987654321-1234567890-1103
[*] Search base: DC=domain,DC=local
[*] Target filter: (objectClass=*)
[ALLOW] AddKeyCredentialLink     Server-Admins (S-1-5-21-123456789-0987654321-1234567890-1105) -> CN=Server Admin,CN=Users,DC=domain,DC=local [ObjectType: ms-DS-Key-Credential-Link (5b47d60f-6090-40b2-9f37-2a4de88f3063)]
[ALLOW] WriteDacl,GenericWrite   Server-Admins (S-1-5-21-123456789-0987654321-1234567890-1105) -> CN=Server Admin,CN=Users,DC=domain,DC=local
[*] Finished: 200 objects scanned, 2 matching ACE(s), 0 DACL parse error(s)
```

### Group memberships only
```
python3 aclcheck.py domain.local/user -principal targetuser -groups-only -k -no-pass -dc-host dc01.domain.local
```
### Inbound ACLs on one object
```
python3 aclcheck.py domain.local/user -target Administrator -k -no-pass -dc-host dc01.domain.local
```

Use `-csv results.csv` to export findings and `-h` for all options.

This is an ACE enumerator, not a complete Windows effective-access engine. Deny ordering, conditional ACEs, claims, and every inheritance edge case are not fully evaluated.
