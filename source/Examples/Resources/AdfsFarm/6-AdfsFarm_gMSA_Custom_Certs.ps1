<#PSScriptInfo
.VERSION 1.0.0
.GUID 312357bb-6e67-4463-903d-9b2428f73d67
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT (c) DSC Community. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/X-Guardian/AdfsDsc/blob/master/LICENSE
.PROJECTURI https://github.com/X-Guardian/AdfsDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES Updated author and copyright notice.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module AdfsDsc

<#
    .DESCRIPTION
        This configuration will create the first node in an Active Directory Federation Services (AD FS) server farm
        using the Windows Internal Database (WID) on the local server computer.

        The certificate with the specified Certificate DNS name will be used as the SSL certificate and the service
        communications certificate. The certificate with the specified signing certificate DNS name will be used as
        the signing certificate and the certificate with the specified decryption certificate DNS name will be used
        for the decryption certificate.

        The group Managed Service Account specified in the GroupServiceAccountIdentifier parameter will be used for the
        service account.
#>

Configuration AdfsFarm_gMSA_Custom_Certs
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdminCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        WindowsFeature InstallAdfs
        {
            Name = 'ADFS-Federation'
        }

        AdfsFarm Contoso
        {
            FederationServiceName         = 'fs.corp.contoso.com'
            FederationServiceDisplayName  = 'Contoso ADFS Service'
            CertificateDnsName            = 'fs.corp.contoso.com'
            SigningCertificateDnsName     = 'ADFS Signing - fs.corp.contoso.com'
            DecryptionCertificateDnsName  = 'ADFS Encryption - fs.corp.contoso.com'
            GroupServiceAccountIdentifier = 'contoso\adfsgmsa$'
            Credential                    = $DomainAdminCredential
        }
    }
}
