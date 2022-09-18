CertUiExts
==========

[![azure devops](https://dev.azure.com/nexiom/CertUiExts/_apis/build/status/CertUiExts)](https://dev.azure.com/nexiom/CertUiExts/_build/latest?definitionId=1)
[![license](https://img.shields.io/github/license/ralish/QueryHardwareSecurity)](https://choosealicense.com/licenses/mit/)

A library which extends Windows cryptography support for displaying additional OIDs and associated certificate extensions.

- [Requirements](#requirements)
- [Setup](#setup)
  - [Installing](#installing)
  - [Uninstalling](#uninstalling)
- [Usage](#usage)
- [Object identifiers (OIDs)](#object-identifiers-oids)
  - [Active Directory](#active-directory)
  - [ASP.NET Core](#aspnet-core)
  - [Azure AD](#azure-ad)
  - [Intune](#intune)
- [Security](#security)
  - [Build security](#build-security)
  - [Windows integration](#windows-integration)
- [License](#license)

Requirements
------------

- Windows Vista or Server 2008 (or later)
- Universal C Runtime (UCRT)  
  *Built-in since Windows 10 and Server 2016*

Setup
-----

### Installing

1. Download the [latest release](https://github.com/ralish/CertUiExts/releases) which matches your Windows architecture (x86 or x64)
2. Unpack the archive to a location which is read-only for non-Administrators (e.g. `C:\Program Files\CertUiExts`)
3. From an elevated command-line run the registration utility to install: `CertUiExtsReg.exe /i`

### Uninstalling

1. From an elevated command-line run the registration utility to uninstall: `CertUiExtsReg.exe /u`
2. Delete the directory in which the files were unpacked (e.g. `C:\Program Files\CertUiExts`)

Usage
-----

The library registers its supported OIDs with the Windows cryptographic services, allowing applications which use the standard operating system cryptographic APIs to benefit from the custom OID formatting functions without any changes. This capability applies to both GUI and CLI applications.

An example of the Windows certificate UI displaying Azure AD OIDs:

![Certificate UI](doc/CertUI.png)

The same certificate displayed using the `Certutil` utility:

```plain
C:\>Certutil -dump example.cer
X509 Certificate:
Version: 3
...
Certificate Extensions: 7
    2.5.29.19: Flags = 1(Critical), Length = 2
    Basic Constraints
        Subject Type=End Entity
        Path Length Constraint=None

    2.5.29.37: Flags = 1(Critical), Length = c
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)

    1.2.840.113556.1.5.284.2: Flags = 0, Length = 13
    Azure AD: Device ID
        <snip>

    1.2.840.113556.1.5.284.3: Flags = 0, Length = 13
    Azure AD: User ID
        <snip>

    1.2.840.113556.1.5.284.5: Flags = 0, Length = 13
    Azure AD: Tenant ID
        <snip>

    1.2.840.113556.1.5.284.8: Flags = 0, Length = 5
    Azure AD: Tenant Region
        Oceania (OC)

    1.2.840.113556.1.5.284.7: Flags = 0, Length = 4
    Azure AD: Join Type
        Joined (1)
...
CertUtil: -dump command completed successfully.
```

Object identifiers (OIDs)
-------------------------

### Active Directory

| OID                            | Description                    |
| ------------------------------ | ------------------------------ |
| `1.3.6.1.4.1.311.25.2`         | CA Security                    |
| `1.3.6.1.4.1.311.25.2.1`       | Object SID                     |

### ASP.NET Core

| OID                            | Description                    |
| ------------------------------ | ------------------------------ |
| `1.3.6.1.4.1.311.84.1.1`       | HTTPS Development Certificate  |

### Azure AD

| OID                            | Description                    |
| ------------------------------ | ------------------------------ |
| `1.2.840.113556.1.5.284.1`     | NTDS-DSA Invocation ID         |
| `1.2.840.113556.1.5.284.2`     | Device ID                      |
| `1.2.840.113556.1.5.284.3`     | User ID                        |
| `1.2.840.113556.1.5.284.4`     | Domain ID                      |
| `1.2.840.113556.1.5.284.5`     | Tenant ID                      |
| `1.2.840.113556.1.5.284.7`     | Join Type                      |
| `1.2.840.113556.1.5.284.8`     | Tenant Region                  |

### Intune

| OID                            | Description                    |
| ------------------------------ | ------------------------------ |
| `1.2.840.113556.5.4`           | Device ID                      |
| `1.2.840.113556.5.6`           | Account ID                     |
| `1.2.840.113556.5.10`          | User ID                        |
| `1.2.840.113556.5.14`          | AAD Tenant ID                  |

Security
--------

### Build security

The extension library and registration utility are built with support for the latest exploit mitigation features.

Compilation features:

- Buffer Security Check (`/GS`)
- Control Flow Guard (CFG) (`/guard:cf`)
- EH Continuation (EHCONT) metadata (*x64 only*) (`/guard:ehcont`)

Linker features:

- Data Execution Prevention (DEP) (`/NXCOMPAT`)
- Address Space Layout Randomisation (ASLR) (`/DYNAMICBASE`)
- High-entropy 64-bit ASLR (*x64 only*) (`/HIGHENTROPYVA`)
- Control-flow Enforcement Technology (CET) Shadow Stack (`/CETCOMPAT`)
- Reproducible (aka. deterministic) builds (`/Brepro`)

Many of these mitigations require operating system support. On older Windows releases they will simply be ignored.

Binaries are built using Azure Pipelines with the build steps located in [azure-pipelines.yml](azure-pipelines.yml).

### Windows integration

The library uses documented Windows cryptographic interfaces to support displaying additional OIDs and formatting their extension data:

- [CryptEnumOIDInfo](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumoidinfo)
- [CryptFindOIDInfo](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptfindoidinfo)
- [CryptFormatObject](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptformatobject)

All of these functions only take public information in certificates. Private cryptographic material is never passed to the library.

Registration and deregistration of the OID information and formatting functions is performed via the following documented APIs:

- [CryptRegisterOIDFunction](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptregisteroidfunction)
- [CryptRegisterOIDInfo](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptregisteroidinfo)
- [CryptUnregisterOIDFunction](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptunregisteroidfunction)
- [CryptUnregisterOIDInfo](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptunregisteroidinfo)

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
