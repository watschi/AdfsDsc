$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$global:DscResourceFriendlyName = 'AdfsFarm'
$script:dscResourceName = "MSFT_$global:DscResourceFriendlyName"

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

# Begin Testing

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        Set-StrictMode -Version 2.0

        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($global:psModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get     = 'Get-AdfsConfigurationStatus'
            Install = 'Install-AdfsFarm'
        }

        $mockUserName = 'CONTOSO\SvcAccount'
        $mockPassword = 'DummyPassword'

        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockUserName,
            (ConvertTo-SecureString -String $mockPassword -AsPlainText -Force)
        )

        $mockMSFTCredential = New-CimCredentialInstance -UserName $mockUserName

        $sqlConnectionString = 'TBC'

        $mockResource = @{
            FederationServiceName        = 'sts.contoso.com'
            FederationServiceDisplayName = 'Contoso ADFS Service'
            CertificateThumbprint        = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            SQLConnectionString          = $SQLConnectionString
            Ensure                       = 'Present'
        }

        $mockSigningCertificateDnsName = "ADFS Signing - $($mockResource.FederationServiceName)"
        $mockDecryptionCertificateDnsName = "ADFS Encryption - $($mockResource.FederationServiceName)"

        $mockGsaResource = $mockResource.Clone()
        $mockGsaResource += @{
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
        }

        $mockSaResource = $mockResource.Clone()
        $mockSaResource += @{
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $mockMSFTCredential
        }

        $mockAbsentResource = @{
            FederationServiceName         = $mockResource.FederationServiceName
            CertificateThumbprint         = $null
            FederationServiceDisplayName  = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
            SQLConnectionString           = $null
            Ensure                        = 'Absent'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName         = $mockGsaResource.FederationServiceName
            FederationServiceDisplayName  = $mockGsaResource.FederationServiceDisplayName
            CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
            ServiceAccountCredential      = $mockGsaResource.ServiceAccountCredential
            GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
            SQLConnectionString           = $mockGsaResource.SQLConnectionString
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsFarm\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    Credential            = $mockCredential
                }

                $mockGetAdfsSslCertificateResult = @(
                    @{
                        Hostname        = 'sts.contoso.com'
                        PortNumber      = 443
                        CertificateHash = $mockResource.CertificateThumbprint
                    }
                )

                $mockGetAdfsPropertiesResult = @{
                    HostName    = $mockResource.FederationServiceName
                    DisplayName = $mockResource.FederationServiceDisplayName
                }

                $mockGetCimInstanceServiceGsaRunningResult = @{
                    State     = 'Running'
                    StartName = $mockGsaResource.GroupServiceAccountIdentifier
                }

                $mockGetCimInstanceServiceSaRunningResult = @{
                    State     = 'Running'
                    StartName = $mockSaResource.ServiceAccountCredential.UserName
                }

                $mockGetCimInstanceSecurityTokenServiceResult = @{
                    ConfigurationDatabaseConnectionString = $sqlConnectionString
                }

                $mockGetAdfsCertificateTokenSigningResult = @{
                    Certificate = @{
                        subject = "CN=$mockSigningCertificateDnsName"
                    }
                    IsPrimary   = $true
                }

                $mockGetAdfsCertificateTokenDecryptingResult = @{
                    Certificate = @{
                        subject = $mockDecryptionCertificateDnsName
                    }
                    IsPrimary   = $true
                }

                $mockExceptionErrorMessage = 'UnknownException'
                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                    -ArgumentList @($mockException, $null, 'InvalidOperation', $null)

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-DomainMember
                Mock -CommandName "Assert-$($global:psModuleName)Service"

                Mock -CommandName Get-CimInstance `
                    -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                    -MockWith { $mockGetCimInstanceServiceGsaRunningResult }
                Mock -CommandName Get-CimInstance `
                    -ParameterFilter { `
                        $Namespace -eq 'root/ADFS' -and `
                        $ClassName -eq 'SecurityTokenService' } `
                    -MockWith { $mockGetCimInstanceSecurityTokenServiceResult }
                Mock -CommandName Get-AdfsSslCertificate -MockWith { $mockGetAdfsSslCertificateResult }
                Mock -CommandName Get-AdfsProperties -MockWith { $mockGetAdfsPropertiesResult }
                Mock -CommandName Get-AdfsCertificate `
                    -ParameterFilter { $CertificateType -eq 'Token-Signing' } `
                    -MockWith { $mockGetAdfsCertificateTokenSigningResult }
                Mock -CommandName Get-AdfsCertificate `
                    -ParameterFilter { $CertificateType -eq 'Token-Decrypting' } `
                    -MockWith { $mockGetAdfsCertificateTokenDecryptingResult }
                Mock -CommandName Assert-GroupServiceAccount -MockWith { $true }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is Configured" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'Configured' }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGsaResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGsaResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter {
                        $ClassName -eq 'Win32_Service' -and `
                            $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter {
                        $Namespace -eq 'root/ADFS' -and `
                            $ClassName -eq 'SecurityTokenService' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsProperties -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 1
                }

                Context 'When Get-AdfsSslCertificate throws an exception' {
                    BeforeAll {
                        Mock Get-AdfsSslCertificate -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSslCertificate returns an empty result' {
                    BeforeAll {
                        Mock Get-AdfsSslCertificate
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context "When Get-AdfsCertificate -CertificateType 'Token-Signing' throws an exception" {
                    BeforeAll {
                        Mock Get-AdfsCertificate `
                            -ParameterFilter { $CertificateType -eq 'Token-Signing' } `
                            -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsTokenSigningCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context "When Get-AdfsCertificate -CertificateType 'Token-Signing' returns an empty result" {
                    BeforeAll {
                        Mock Get-AdfsCertificate -ParameterFilter { $CertificateType -eq 'Token-Signing' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsTokenSigningCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context "When Get-AdfsCertificate -CertificateType 'Token-Decrypting' throws an exception" {
                    BeforeAll {
                        Mock Get-AdfsCertificate `
                            -ParameterFilter { $CertificateType -eq 'Token-Decrypting' } `
                            -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsTokenDecryptingCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context "When Get-AdfsCertificate -CertificateType 'Token-Decrypting' returns an empty result" {
                    BeforeAll {
                        Mock Get-AdfsCertificate -ParameterFilter { $CertificateType -eq 'Token-Decrypting' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsTokenDecryptingCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-CimInstance -ClassName Win32_Service returns an empty result' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { $ClassName -eq 'Win32_Service' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsServiceErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When the Service Account is not a group managed service account' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                            -MockWith { $mockGetCimInstanceServiceSaRunningResult }
                        Mock -CommandName Assert-GroupServiceAccount -MockWith { $false }

                        $result = Get-TargetResource @getTargetResourceParameters
                    }

                    foreach ($property in $mockSaResource.Keys)
                    {
                        if ($property -eq 'ServiceAccountCredential')
                        {
                            It "Should return the correct $property property" {
                                $result.ServiceAccountCredential.UserName | Should -Be $mockSaResource.ServiceAccountCredential.UserName
                            }
                        }
                        else
                        {
                            It "Should return the correct $property property" {
                                $result.$property | Should -Be $mockSaResource.$property
                            }
                        }
                    }
                }

                Context 'When Get-CimInstance -ClassName SecurityTokenService throws an exception' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { `
                                $Namespace -eq 'root/ADFS' -and `
                                $ClassName -eq 'SecurityTokenService' } `
                            -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSecurityTokenServiceErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsProperties throws an exception' {
                    BeforeAll {
                        Mock Get-AdfsProperties -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsPropertiesErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is Absent" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'NotConfigured' }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGsaResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsProperties -Exactly -Times 0
                    Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 0
                }
            }
        }

        Describe 'MSFT_AdfsFarm\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaResource.FederationServiceName
                    CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                    Credential                    = $mockCredential
                    GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
                }

                $mockInstallResourceSuccessResult = @{
                    Message = 'The configuration completed successfully.'
                    Context = 'DeploymentSucceeded'
                    Status  = 'Success'
                }

                $mockInstallResourceErrorResult = @{
                    Message = 'The configuration did not complete successfully.'
                    Context = 'DeploymentTask'
                    Status  = 'Error'
                }

                $mockNewCertificateThumbprint = '6F7E9F5543505B943FEEA49E651EDDD8D9D45014'
                $mockNewFederationServiceDisplayName = 'Fabrikam ADFS Service'
                $mockCertificateDnsName = $mockResource.FederationServiceName

                Mock -CommandName $ResourceCommand.Install -MockWith { $mockInstallResourceSuccessResult }

                $localMachineCertPath = 'cert:\LocalMachine\My\'
            }

            Context 'When both credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceDuplicateCredentialErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When neither credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceNeitherCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceNeitherCredentialParameters.Remove('GroupServiceAccountIdentifier')
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceNeitherCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceMissingCredentialErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When both service certificate parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothServiceCertificateParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothServiceCertificateParameters.Add('CertificateDnsName', $mockCertificateDnsName)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothServiceCertificateParameters } |
                        Should -Throw ($script:localizedData.ResourceDuplicateServiceCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When neither service certificate parameters have been specified' {
                BeforeAll {
                    $setTargetResourceNeitherServiceCertificateParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceNeitherServiceCertificateParameters.Remove('CertificateThumbprint')
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceNeitherServiceCertificateParameters } |
                        Should -Throw ($script:localizedData.ResourceMissingServiceCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When the signing certificate DNS Name but not the decryption certificate DNS name parameter has been specified' {
                BeforeAll {
                    $setTargetResourceSigningCertificateDnsNameParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceSigningCertificateDnsNameParameters.Add('SigningCertificateDnsName',
                        $mockSigningCertificateDnsName)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceSigningCertificateDnsNameParameters } |
                        Should -Throw ($script:localizedData.ResourceInvalidSignDecryptCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When the decryption certificate DNS Name but not the signing certificate DNS name parameter has been specified' {
                BeforeAll {
                    $setTargetResourceDecryptionCertificateDnsNameParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceDecryptionCertificateDnsNameParameters.Add('DecryptionCertificateDnsName',
                        $mockDecryptionCertificateDnsName)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceDecryptionCertificateDnsNameParameters } |
                        Should -Throw ($script:localizedData.ResourceInvalidSignDecryptCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When the AdminConfiguration parameter has been specified' {
                BeforeAll {
                    $mockAdminConfiguration = @{
                        Key   = 'DKMContainerDn'
                        Value = 'CN=9530440c-bc84-4fe6-a3f9-8d60162a7bcf,CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com'
                    }

                    $mockAdminConfigurationCimInstance = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_KeyValuePair `
                            -Namespace MSFT_KeyValuePair `
                            -Property $mockAdminConfiguration -ClientOnly
                    )

                    $setTargetResourceAdminConfigurationParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceAdminConfigurationParameters.Add('AdminConfiguration', $mockAdminConfigurationCimInstance)

                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceAdminConfigurationParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName $ResourceCommand.Install `
                        -ParameterFilter {
                        $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName -and
                        $AdminConfiguration.($mockAdminConfiguration.Key) -eq $mockAdminConfiguration.Value
                    } `
                        -Exactly -Times 1
                }
            }

            Context 'When the CertificateDnsName parameter has been specified' {
                BeforeAll {
                    $setTargetResourceCertificateDnsNameParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceCertificateDnsNameParameters.Add('CertificateDnsName', $mockCertificateDnsName)
                    $setTargetResourceCertificateDnsNameParameters.Remove('CertificateThumbprint')

                    $mockGetChildItemCertificateDnsNameResult = @{
                        Thumbprint = '857C8836C1D8217FFFCA0997D0864ED307926C41'
                    }

                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                    Mock Get-ChildItem `
                        -ParameterFilter { $Path -eq $localMachineCertPath -and $DnsName -eq $mockCertificateDnsName } `
                        -MockWith { $mockGetChildItemCertificateDnsNameResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceCertificateDnsNameParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-ChildItem `
                        -ParameterFilter {
                        $Path -eq $localMachineCertPath -and
                        $DnsName -eq $mockCertificateDnsName
                    } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Install `
                        -ParameterFilter {
                        $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName -and
                        $CertificateThumbprint -eq $mockGetChildItemCertificateDnsNameResult.Thumbprint
                    } `
                        -Exactly -Times 1
                }

                Context 'When the Certificate can not be found' {
                    BeforeAll {
                        Mock Get-ChildItem -ParameterFilter { $Path -eq $localMachineCertPath }
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceCertificateDnsNameParameters } |
                            Should -Throw ($script:localizedData.CertificateNotFoundErrorMessage -f
                                $mockCertificateDnsName)
                    }
                }
            }

            Context 'When the SigningCertificateDnsName and DecryptionCertificateDnsName parameters have been specified' {
                BeforeAll {
                    $setTargetResourceSignDecryptCertificateDnsNameParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceSignDecryptCertificateDnsNameParameters.Add('SigningCertificateDnsName',
                        $mockSigningCertificateDnsName)
                    $setTargetResourceSignDecryptCertificateDnsNameParameters.Add('DecryptionCertificateDnsName',
                        $mockDecryptionCertificateDnsName)

                    $mockGetChildItemSigningCertificateResult = @{
                        Thumbprint = '857C8836C1D8217FFFCA0997D0864ED307926C41'
                    }

                    $mockGetChildItemDecryptionCertificateResult = @{
                        Thumbprint = '7F266BBDCCC94D763E39AF655B7D03EEB83AD4AC'
                    }

                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                    Mock Get-ChildItem `
                        -ParameterFilter { $Path -eq $localMachineCertPath -and $DnsName -eq $mockSigningCertificateDnsName } `
                        -MockWith { $mockGetChildItemSigningCertificateResult }

                    Mock Get-ChildItem `
                        -ParameterFilter { $Path -eq $localMachineCertPath -and $DnsName -eq $mockDecryptionCertificateDnsName } `
                        -MockWith { $mockGetChildItemDecryptionCertificateResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceSignDecryptCertificateDnsNameParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-ChildItem `
                        -ParameterFilter {
                        $Path -eq $localMachineCertPath -and
                        $DnsName -eq $mockSigningCertificateDnsName
                    } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-ChildItem `
                        -ParameterFilter {
                        $Path -eq $localMachineCertPath -and
                        $DnsName -eq $mockDecryptionCertificateDnsName
                    } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Install `
                        -ParameterFilter {
                        $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName -and
                        $SigningCertificateThumbprint -eq $mockGetChildItemSigningCertificateResult.Thumbprint -and
                        $DecryptionCertificateThumbprint -eq $mockGetChildItemDecryptionCertificateResult.Thumbprint
                    } `
                        -Exactly -Times 1
                }

                Context 'When the Signing Certificate can not be found' {
                    BeforeAll {
                        Mock Get-ChildItem `
                            -ParameterFilter { $Path -eq $localMachineCertPath -and $DnsName -eq $mockSigningCertificateDnsName } `
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceSignDecryptCertificateDnsNameParameters } |
                            Should -Throw ($script:localizedData.CertificateNotFoundErrorMessage -f
                                $mockSigningCertificateDnsName)
                    }
                }

                Context 'When the Decrypting Certificate can not be found' {
                    BeforeAll {
                        Mock Get-ChildItem `
                            -ParameterFilter { $Path -eq $localMachineCertPath -and $DnsName -eq $mockDecryptionCertificateDnsName } `
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceSignDecryptCertificateDnsNameParameters } |
                            Should -Throw ($script:localizedData.CertificateNotFoundErrorMessage -f
                                $mockDecryptionCertificateDnsName)
                    }
                }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is not installed" {
                BeforeAll {
                    $mockGetTargetResourceAbsentResult = @{
                        Ensure = 'Absent'
                    }

                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName $ResourceCommand.Install `
                        -ParameterFilter { $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1
                }

                Context "When $($ResourceCommand.Install) throws System.IO.FileNotFoundException" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { throw New-Object System.IO.FileNotFoundException }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName $ResourceCommand.Install `
                            -ParameterFilter { $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName } `
                            -Exactly -Times 1
                    }
                }

                Context "When $($ResourceCommand.Install) throws an exception" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                            $script:localizedData.InstallationErrorMessage -f $setTargetResourceParameters.FederationServiceName)
                    }
                }

                Context "When $($ResourceCommand.Install) returns a result with a status of 'Error'" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { $mockInstallResourceErrorResult }
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                            $mockInstallResourceErrorResult.Message)
                    }
                }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is installed" {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }
            }
        }

        Describe 'MSFT_AdfsFarm\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    CertificateThumbprint = $mockResource.CertificateThumbprint
                    Credential            = $mockCredential
                }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                It 'Should return $true' {
                    Test-TargetResource @testTargetResourceParameters | Should -BeTrue
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1

                }
            }

            Context "When the $($global:DscResourceFriendlyName) Resource is not installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                It 'Should return $false' {
                    Test-TargetResource @testTargetResourceParameters | Should -BeFalse
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
