#pragma once

// *********************************************************
// ***         Active Directory Domain Services          ***
// *********************************************************

/*
 * [MS-WCCE]: Windows Client Certificate Enrollment Protocol
 * Section 2.2.2.7.7.4 szOID_NTDS_CA_SECURITY_EXT
 *
 * Certificate-based authentication changes on Windows domain controllers
 * https://support.microsoft.com/kb/5014754
 */
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

/*
 * Refer to comments for OID: 1.3.6.1.4.1.311.25.2
 */
#define wszNTDS_OBJECTSID_NAME L"AD DS: Object SID"
#define szNTDS_OBJECTSID_OID "1.3.6.1.4.1.311.25.2.1"
#define cbNTDS_OBJECTSID_OID_VALUE (DWORD)10
#define cbNTDS_OBJECTSID_OID_TLV (cbNTDS_OBJECTSID_OID_VALUE + 2)


// *********************************************************
// ***                     Azure AD                      ***
// *********************************************************

/*
 * [MS-DVRE]: Device Registration Enrollment Protocol
 * Section 3.1.4.2.1: New Request Processing
 *
 * [MS-DVRJ]: Device Registration Join Protocol
 * Section 3.1.5.1.1.3: Processing Details
 */
#define wszAAD_NTDS_DSA_IID_NAME L"Azure AD: NTDS-DSA Invocation ID"
#define szAAD_NTDS_DSA_IID_OID "1.2.840.113556.1.5.284.1"

/*
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
#define wszAAD_DEVICE_ID_NAME L"Azure AD: Device ID"
#define szAAD_DEVICE_ID_OID "1.2.840.113556.1.5.284.2"

/*
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
#define wszAAD_USER_ID_NAME L"Azure AD: User ID"
#define szAAD_USER_ID_OID "1.2.840.113556.1.5.284.3"

/*
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
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
// ***                      Intune                       ***
// *********************************************************

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
