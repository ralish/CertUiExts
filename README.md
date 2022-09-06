CertUiExts
==========

[![azure devops](https://dev.azure.com/nexiom/CertUiExts/_apis/build/status/CertUiExts?branchName=stable)](https://dev.azure.com/nexiom/CertUiExts/_build/latest?definitionId=1&branchName=stable)
[![license](https://img.shields.io/github/license/ralish/QueryHardwareSecurity)](https://choosealicense.com/licenses/mit/)

A library which extends Windows cryptography support for displaying additional OIDs and associated certificate extensions.

- [Requirements](#requirements)
- [Supported OIDs](#supported-oids)
  - [Active Directory](#active-directory)
  - [Azure AD](#azure-ad)
  - [Intune](#intune)
- [License](#license)

Requirements
------------

- Windows Vista or Server 2008 (or later)
- Universal C Runtime (UCRT)  
  *Built-in since Windows 10 and Server 2016.*

Supported OIDs
--------------

### Active Directory

| OID                            | Description               |
| ------------------------------ | ------------------------- |
| `1.3.6.1.4.1.311.25.2`         | CA Security               |
| `1.3.6.1.4.1.311.25.2.1`       | Object SID                |

### Azure AD

| OID                            | Description               |
| ------------------------------ | ------------------------- |
| `1.2.840.113556.1.5.284.1`     | NTDS-DSA Invocation ID    |
| `1.2.840.113556.1.5.284.2`     | Device ID                 |
| `1.2.840.113556.1.5.284.3`     | User ID                   |
| `1.2.840.113556.1.5.284.4`     | Domain ID                 |
| `1.2.840.113556.1.5.284.5`     | Tenant ID                 |
| `1.2.840.113556.1.5.284.7`     | Join Type                 |
| `1.2.840.113556.1.5.284.8`     | Tenant Region             |

### Intune

| OID                            | Description               |
| ------------------------------ | ------------------------- |
| `1.2.840.113556.5.4`           | Device ID                 |
| `1.2.840.113556.5.4`           | Account ID                |
| `1.2.840.113556.5.14`          | AAD Tenant ID             |

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
