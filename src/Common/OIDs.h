#pragma once

// *********************************************************
// ***         Active Directory Domain Services          ***
// ***                1.3.6.1.4.1.311.25                 ***
// *********************************************************

/*
 * iso(1) / identified-organization(3) / dod(6)
 * internet(1) / private(4) / enterprise(1)
 * microsoft(311) / directory-service(25)
 */

// [MS-WCCE]: Windows Client Certificate Enrollment Protocol
// Section 2.2.2.7.7.4 szOID_NTDS_CA_SECURITY_EXT
//
// Certificate-based authentication changes on Windows domain controllers
// https://support.microsoft.com/kb/5014754
#define wszNTDS_CA_SECURITY_EXT_NAME L"AD DS: CA Security"
#define szNTDS_CA_SECURITY_EXT_OID "1.3.6.1.4.1.311.25.2"

// Maximum component lengths
//
// NetBIOS domain name:          15 chars
// User account name:            20 chars
// Security Identifier (SID):   183 chars
//
// That's 436 bytes with Unicode encoding. We need some extra space for other
// text so round up to 512 bytes (254 chars). In practice, actual SIDs in
// certificates will be *much* smaller leaving plenty of room.
#define cbNTDS_CA_SECURITY_EXT_BUFFER (DWORD)512

// Minimum ASN.1 structure size
//
// Type and length bytes:       10 bytes
// OID value bytes:             10 bytes
// SID value bytes (minimum):    7 bytes
//
// A real SID ought to be much bigger, but anything less than 7 bytes in the
// octet string value is definitely malformed.
#define cbNTDS_CA_SECURITY_EXT_ASN_MIN (DWORD)27

// Refer to comments for OID: 1.3.6.1.4.1.311.25.2
#define wszNTDS_OBJECTSID_NAME L"AD DS: Object SID"
#define szNTDS_OBJECTSID_OID "1.3.6.1.4.1.311.25.2.1"
#define cbNTDS_OBJECTSID_OID_VALUE (DWORD)10
#define cbNTDS_OBJECTSID_OID_TLV (cbNTDS_OBJECTSID_OID_VALUE + 2)


// *********************************************************
// ***                   ASP.NET Core                    ***
// ***                1.3.6.1.4.1.311.84                 ***
// *********************************************************

/*
 * iso(1) / identified-organization(3) / dod(6)
 * internet(1) / private(4) / enterprise(1)
 * microsoft(311) / unknown(84)
 */

// Undocumented but open-source
// https://github.com/dotnet/aspnetcore/blob/main/src/Shared/CertificateGeneration/CertificateManager.cs
#define wszASPNETCORE_HTTPS_DEV_CERT_NAME L"ASP.NET Core: HTTPS Development Certificate"
#define szASPNETCORE_HTTPS_DEV_CERT_OID "1.3.6.1.4.1.311.84.1.1"
#define cbASPNETCORE_HTTPS_DEV_CERT_BUFFER ((DWORD)16 * sizeof(WCHAR))


// *********************************************************
// ***                   Authenticode                    ***
// ***                 1.3.6.1.4.1.311.2                 ***
// *********************************************************

/*
 * iso(1) / identified-organization(3) / dod(6)
 * internet(1) / private(4) / enterprise(1)
 * microsoft(311) / authenticode(25)
 */

/*
 * Attribute names deliberately omit an "Authenticode: ..." prefix for user
 * interface consistency alongside the existing set of recognised attributes.
 */

#define wszAUTHENTICODE_SPC_STATEMENT_TYPE_NAME L"SPC Statement Type"
#define szAUTHENTICODE_SPC_STATEMENT_TYPE_OID "1.3.6.1.4.1.311.2.1.11"
#define cbAUTHENTICODE_SPC_STATEMENT_TYPE_BUFFER ((DWORD)16 * sizeof(WCHAR))

#define wszAUTHENTICODE_SPC_SP_OPUS_INFO_NAME L"SPC Publisher Information"
#define szAUTHENTICODE_SPC_SP_OPUS_INFO_OID "1.3.6.1.4.1.311.2.1.12"

//#define wszAUTHENTICODE_RFC3161_COUNTERSIGN_NAME L"Timestamping Signature"
//#define szAUTHENTICODE_RFC3161_COUNTERSIGN_OID "1.3.6.1.4.1.311.3.3.1"


// *********************************************************
// ***                     Azure AD                      ***
// ***              1.2.840.113556.1.5.284               ***
// *********************************************************

/*
 * iso(1) / member-body(2) / us(840)
 * microsoft(113556) / active-directory(1) / unknown(5)
 * device-registration-service(284)
 */

// [MS-DVRE]: Device Registration Enrollment Protocol
// Section 3.1.4.2.1: New Request Processing
//
// [MS-DVRJ]: Device Registration Join Protocol
// Section 3.1.5.1.1.3: Processing Details
#define wszAAD_NTDS_DSA_IID_NAME L"Azure AD: NTDS-DSA Invocation ID"
#define szAAD_NTDS_DSA_IID_OID "1.2.840.113556.1.5.284.1"

// Refer to comments for OID: 1.2.840.113556.1.5.284.1
#define wszAAD_DEVICE_ID_NAME L"Azure AD: Device ID"
#define szAAD_DEVICE_ID_OID "1.2.840.113556.1.5.284.2"

// Refer to comments for OID: 1.2.840.113556.1.5.284.1
#define wszAAD_USER_ID_NAME L"Azure AD: User ID"
#define szAAD_USER_ID_OID "1.2.840.113556.1.5.284.3"

// Refer to comments for OID: 1.2.840.113556.1.5.284.1
#define wszAAD_DOMAIN_ID_NAME L"Azure AD: Domain ID"
#define szAAD_DOMAIN_ID_OID "1.2.840.113556.1.5.284.4"

// Undocumented
#define wszAAD_TENANT_ID_NAME L"Azure AD: Tenant ID"
#define szAAD_TENANT_ID_OID "1.2.840.113556.1.5.284.5"

// Undocumented
#define wszAAD_JOIN_TYPE_NAME L"Azure AD: Join Type"
#define szAAD_JOIN_TYPE_OID "1.2.840.113556.1.5.284.7"
#define cbAAD_JOIN_TYPE_BUFFER ((DWORD)16 * sizeof(WCHAR))

// Undocumented
#define wszAAD_TENANT_REGION_NAME L"Azure AD: Tenant Region"
#define szAAD_TENANT_REGION_OID "1.2.840.113556.1.5.284.8"
#define cbAAD_TENANT_REGION_BUFFER ((DWORD)32 * sizeof(WCHAR))


// *********************************************************
// ***                 CA/Browser Forum                  ***
// ***                     2.23.140                      ***
// *********************************************************

/*
 * joint-iso-itu-t(2) / international-organizations(23)
 * ca-browser-forum(140)
 */

// certificate-policies(1) -> ev-guidelines(1)
#define wszCAB_CERTPOL_TLS_EV_NAME L"CA/Browser Forum: Extended Validation (EV) TLS Certificate"
#define szCAB_CERTPOL_TLS_EV_OID "2.23.140.1.1"

// certificate-policies(1) -> baseline-requirements(2) -> domain-validated(1)
#define wszCAB_CERTPOL_TLS_DV_NAME L"CA/Browser Forum: Domain Validated (DV) TLS Certificate"
#define szCAB_CERTPOL_TLS_DV_OID "2.23.140.1.2.1"

// certificate-policies(1) -> baseline-requirements(2) -> organization-validated(2)
#define wszCAB_CERTPOL_TLS_OV_NAME L"CA/Browser Forum: Organization Validated (OV) TLS Certificate"
#define szCAB_CERTPOL_TLS_OV_OID "2.23.140.1.2.2"

// certificate-policies(1) -> baseline-requirements(2) -> individual-validated(3)
#define wszCAB_CERTPOL_TLS_IV_NAME L"CA/Browser Forum: Individual Validated (IV) TLS Certificate"
#define szCAB_CERTPOL_TLS_IV_OID "2.23.140.1.2.3"

// certificate-policies(1) -> extended-validation-codesigning(3)
#define wszCAB_CERTPOL_CS_EV_NAME L"CA/Browser Forum: Extended Validation (EV) Code Signing Certificate"
#define szCAB_CERTPOL_CS_EV_OID "2.23.140.1.3"

// certificate-policies(1) -> code-signing-requirements(4) -> code-signing(1)
#define wszCAB_CERTPOL_CS_NAME L"CA/Browser Forum: Code Signing Certificate"
#define szCAB_CERTPOL_CS_OID "2.23.140.1.4.1"

// certificate-policies(1) -> code-signing-requirements(4) -> timestamping(2)
#define wszCAB_CERTPOL_TS_NAME L"CA/Browser Forum: Timestamping Certificate"
#define szCAB_CERTPOL_TS_OID "2.23.140.1.4.2"

// certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> legacy(1)
#define wszCAB_CERTPOL_SMIME_MV_LEGACY_NAME L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Legacy)"
#define szCAB_CERTPOL_SMIME_MV_LEGACY_OID "2.23.140.1.5.1.1"

// certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> multipurpose(2)
#define wszCAB_CERTPOL_SMIME_MV_MULTI_NAME L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Multipurpose)"
#define szCAB_CERTPOL_SMIME_MV_MULTI_OID "2.23.140.1.5.1.2"

// certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> strict(3)
#define wszCAB_CERTPOL_SMIME_MV_STRICT_NAME L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Strict)"
#define szCAB_CERTPOL_SMIME_MV_STRICT_OID "2.23.140.1.5.1.3"

// certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> legacy(1)
#define wszCAB_CERTPOL_SMIME_OV_LEGACY_NAME L"CA/Browser Forum: Organization Validated S/MIME Certificate (Legacy)"
#define szCAB_CERTPOL_SMIME_OV_LEGACY_OID "2.23.140.1.5.2.1"

// certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> multipurpose(2)
#define wszCAB_CERTPOL_SMIME_OV_MULTI_NAME L"CA/Browser Forum: Organization Validated S/MIME Certificate (Multipurpose)"
#define szCAB_CERTPOL_SMIME_OV_MULTI_OID "2.23.140.1.5.2.2"

// certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> strict(3)
#define wszCAB_CERTPOL_SMIME_OV_STRICT_NAME L"CA/Browser Forum: Organization Validated S/MIME Certificate (Strict)"
#define szCAB_CERTPOL_SMIME_OV_STRICT_OID "2.23.140.1.5.2.3"

// certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> legacy(1)
#define wszCAB_CERTPOL_SMIME_SV_LEGACY_NAME L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Legacy)"
#define szCAB_CERTPOL_SMIME_SV_LEGACY_OID "2.23.140.1.5.3.1"

// certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> multipurpose(2)
#define wszCAB_CERTPOL_SMIME_SV_MULTI_NAME L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Multipurpose)"
#define szCAB_CERTPOL_SMIME_SV_MULTI_OID "2.23.140.1.5.3.2"

// certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> strict(3)
#define wszCAB_CERTPOL_SMIME_SV_STRICT_NAME L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Strict)"
#define szCAB_CERTPOL_SMIME_SV_STRICT_OID "2.23.140.1.5.3.3"

// certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> legacy(1)
#define wszCAB_CERTPOL_SMIME_IV_LEGACY_NAME L"CA/Browser Forum: Individual Validated S/MIME Certificate (Legacy)"
#define szCAB_CERTPOL_SMIME_IV_LEGACY_OID "2.23.140.1.5.4.1"

// certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> multipurpose(2)
#define wszCAB_CERTPOL_SMIME_IV_MULTI_NAME L"CA/Browser Forum: Individual Validated S/MIME Certificate (Multipurpose)"
#define szCAB_CERTPOL_SMIME_IV_MULTI_OID "2.23.140.1.5.4.2"

// certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> strict(3)
#define wszCAB_CERTPOL_SMIME_IV_STRICT_NAME L"CA/Browser Forum: Individual Validated S/MIME Certificate (Strict)"
#define szCAB_CERTPOL_SMIME_IV_STRICT_OID "2.23.140.1.5.4.3"


// *********************************************************
// ***                     DigiCert                      ***
// ***                 2.16.840.1.114412                 ***
// *********************************************************

/*
 * joint-iso-itu-t(2) / country(16) / us(840)
 * organization(1) / digicert(114412)
 */

#define wszDIGICERT_CERTPOL_TLS_OV_NAME L"DigiCert: Organization Validated (OV) TLS Certificate"
#define szDIGICERT_CERTPOL_TLS_OV_OID "2.16.840.1.114412.1.1"

#define wszDIGICERT_CERTPOL_TLS_DV_NAME L"DigiCert: Domain Validated (DV) TLS Certificate"
#define szDIGICERT_CERTPOL_TLS_DV_OID "2.16.840.1.114412.1.2"

#define wszDIGICERT_CERTPOL_TLS_EV_NAME L"DigiCert: Extended Validation (EV) TLS Certificate"
#define szDIGICERT_CERTPOL_TLS_EV_OID "2.16.840.1.114412.2.1"

#define wszDIGICERT_CERTPOL_CS_NAME L"DigiCert: Code Signing Certificate"
#define szDIGICERT_CERTPOL_CS_OID "2.16.840.1.114412.3.1.1"

#define wszDIGICERT_CERTPOL_CS_EV_NAME L"DigiCert: Extended Validation (EV) Code Signing Certificate"
#define szDIGICERT_CERTPOL_CS_EV_OID "2.16.840.1.114412.3.2"

#define wszDIGICERT_CERTPOL_CS_WK_NAME L"DigiCert: Windows Kernel Driver Code Signing Certificate"
#define szDIGICERT_CERTPOL_CS_WK_OID "2.16.840.1.114412.3.11"

#define wszDIGICERT_CERTPOL_TS_NAME L"DigiCert: Timestamping Certificate"
#define szDIGICERT_CERTPOL_TS_OID "2.16.840.1.114412.7.1"


// *********************************************************
// ***                      Intune                       ***
// ***                 1.2.840.113556.5                  ***
// *********************************************************

/*
 * iso(1) / member-body(2) / us(840)
 * microsoft(113556) / unknown(5)
 */

// 1.2.840.113556.5.3
// Found in certca.dll, CertEnroll.dll, CertEnrollUI.dll

// Undocumented
#define wszINTUNE_DEVICE_ID_NAME L"Intune: Device ID"
#define szINTUNE_DEVICE_ID_OID "1.2.840.113556.5.4"

// Undocumented
#define wszINTUNE_ACCOUNT_ID_NAME L"Intune: Account ID"
#define szINTUNE_ACCOUNT_ID_OID "1.2.840.113556.5.6"

// 1.2.840.113556.5.10
// Found in certca.dll, CertEnroll.dll, CertEnrollUI.dll

// Undocumented
#define wszINTUNE_USER_ID_NAME L"Intune: User ID"
#define szINTUNE_USER_ID_OID "1.2.840.113556.5.10"

// Undocumented
#define wszINTUNE_UNKNOWN_11_NAME L"Intune: Unknown (11)"
#define szINTUNE_UNKNOWN_11_OID "1.2.840.113556.5.11"

// Undocumented
#define wszINTUNE_AAD_TENANT_ID_NAME L"Intune: AAD Tenant ID"
#define szINTUNE_AAD_TENANT_ID_OID "1.2.840.113556.5.14"


// *********************************************************
// ***                      Sectigo                      ***
// ***                 1.3.6.1.4.1.6449                  ***
// *********************************************************

/*
 * iso(1) / identified-organization(3) / dod(6)
 * internet(1) / private(4) / enterprise(1)
 * sectigo(6449)
 */

// Personal Secure Email
#define wszSECTIGO_CERTPOL_SMIME_C1_NAME L"Sectigo: S/MIME Certificate (Class 1)"
#define szSECTIGO_CERTPOL_SMIME_C1_OID "1.3.6.1.4.1.6449.1.2.1.1.1"

// Secure Server
#define wszSECTIGO_CERTPOL_TLS_NAME L"Sectigo: TLS Certificate"
#define szSECTIGO_CERTPOL_TLS_OID "1.3.6.1.4.1.6449.1.2.1.3.1"

// Software Publisher
#define wszSECTIGO_CERTPOL_CS_NAME L"Sectigo: Code Signing Certificate"
#define szSECTIGO_CERTPOL_CS_OID "1.3.6.1.4.1.6449.1.2.1.3.2"

// InstantSSL
#define wszSECTIGO_CERTPOL_TLS_OV_NAME L"Sectigo: Organization Validated (OV) TLS Certificate"
#define szSECTIGO_CERTPOL_TLS_OV_OID "1.3.6.1.4.1.6449.1.2.1.3.4"

// Corporate Secure Email
#define wszSECTIGO_CERTPOL_SMIME_C2_NAME L"Sectigo: S/MIME Certificate (Class 2)"
#define szSECTIGO_CERTPOL_SMIME_C2_OID "1.3.6.1.4.1.6449.1.2.1.3.5"

// Enterprise-Wide Secure Email
#define wszSECTIGO_CERTPOL_SMIME_C3_NAME L"Sectigo: S/MIME Certificate (Class 3)"
#define szSECTIGO_CERTPOL_SMIME_C3_OID "1.3.6.1.4.1.6449.1.2.1.3.6"

#define wszSECTIGO_CERTPOL_TS_NAME L"Sectigo: Timestamping Certificate"
#define szSECTIGO_CERTPOL_TS_OID "1.3.6.1.4.1.6449.1.2.1.3.8"

#define wszSECTIGO_CERTPOL_TLS_EV_NAME L"Sectigo: Extended Validation (EV) TLS Certificate"
#define szSECTIGO_CERTPOL_TLS_EV_OID "1.3.6.1.4.1.6449.1.2.1.5.1"

#define wszSECTIGO_CERTPOL_CS_EV_NAME L"Sectigo: Extended Validation (EV) Code Signing Certificate"
#define szSECTIGO_CERTPOL_CS_EV_OID "1.3.6.1.4.1.6449.1.2.1.6.1"

#define wszSECTIGO_CERTPOL_DS_LOCAL_NAME L"Sectigo: Document Signing (local)"
#define szSECTIGO_CERTPOL_DS_LOCAL_OID "1.3.6.1.4.1.6449.1.2.1.6.6"

#define wszSECTIGO_CERTPOL_DS_REMOTE_NAME L"Sectigo: Document Signing (remote)"
#define szSECTIGO_CERTPOL_DS_REMOTE_OID "1.3.6.1.4.1.6449.1.2.1.6.7"

#define wszSECTIGO_CERTPOL_DS_ETP_NAME L"Sectigo: Document Signing (external trusted partner)"
#define szSECTIGO_CERTPOL_DS_ETP_OID "1.3.6.1.4.1.6449.1.2.1.6.8"

// DV Secure Server
#define wszSECTIGO_CERTPOL_TLS_DV_NAME L"Sectigo: Domain Validated (DV) TLS Certificate"
#define szSECTIGO_CERTPOL_TLS_DV_OID "1.3.6.1.4.1.6449.1.2.2.7"
