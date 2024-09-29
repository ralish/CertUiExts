#pragma once

/*
 * CA Security
 * 1.3.6.1.4.1.311.25.2
 */

// Requested buffer size for formatted output
//
// The maximum lengths of each component are:
// NetBIOS domain name:          15 chars
// User account name:            20 chars
// Security Identifier (SID):   183 chars
//
// That's 436 bytes with Unicode encoding. We need some extra space for
// other text so round up to 512 bytes (254 chars). In practice, actual
// SIDs in certificates will be *much* smaller leaving plenty of room.
#define cbCA_SECURITY_EXT_BUFFER (DWORD)512

// Minimum size of a valid ASN.1 structure
//
// Type and length bytes:       10 bytes
// OID value bytes:             10 bytes
// SID value bytes (minimum):    7 bytes
//
// A real SID ought to be much bigger, but anything less than 7 bytes
// in the octet string value is definitely malformed.
#define cbCA_SECURITY_EXT_ASN_MIN (DWORD)27


/*
 * Object SID
 * 1.3.6.1.4.1.311.25.2.1
 */

// To check the CA Security extension encodes the expected OID
#define szOBJECTSID_OID "1.3.6.1.4.1.311.25.2.1"

// Size of the OID when encoded in ASN.1. Object identifiers are
// encoded in a unique format which is more efficient than a simple
// ASCII string, hence the much smaller size.
#define cbOBJECTSID_OID_VALUE (DWORD)10

// Size of the OID (see above) including the type and length bytes
#define cbOBJECTSID_OID_TLV (cbOBJECTSID_OID_VALUE + (DWORD)2)
