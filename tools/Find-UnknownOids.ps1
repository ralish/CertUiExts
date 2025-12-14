<#
    Finds unknown certificate extensions & EKUs present in certificates in the
    Windows certificate store.
#>

[CmdletBinding()]
Param()

$UnknownOids = [Collections.Generic.Dictionary[string, Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]]::new()

$Certs = Get-ChildItem -Path 'Cert:\' -Recurse | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509Certificate2] }
foreach ($Cert in $Certs) {
    # Unknown extensions
    foreach ($Extension in $Cert.Extensions) {
        if (![String]::IsNullOrWhiteSpace($Extension.Oid.FriendlyName)) { continue }

        if ($UnknownOids.ContainsKey($Extension.Oid.Value)) {
            $UnknownOids[$Extension.Oid.Value].Add($Cert)
            continue
        }

        $UnknownExtCerts = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        $UnknownExtCerts.Add($Cert)
        $UnknownOids.Add($Extension.Oid.Value, $UnknownExtCerts)
    }

    # Unknown EKUs
    foreach ($Eku in $Cert.EnhancedKeyUsageList) {
        if (![String]::IsNullOrWhiteSpace($Eku.FriendlyName)) { continue }

        if ($UnknownOids.ContainsKey($Eku.ObjectId)) {
            $UnknownOids[$Eku.ObjectId].Add($Cert)
            continue
        }

        $UnknownEkuCerts = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        $UnknownEkuCerts.Add($Cert)
        $UnknownOids.Add($Eku.ObjectId, $UnknownEkuCerts)
    }
}

return $UnknownOids
