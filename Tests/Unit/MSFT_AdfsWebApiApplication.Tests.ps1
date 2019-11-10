$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsWebApiApplication'

$moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git',
        (Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit

try
{
    InModuleScope $Global:DSCResourceName {
        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get    = 'Get-AdfsWebApiApplication'
            Set    = 'Set-AdfsWebApiApplication'
            Add    = 'Add-AdfsWebApiApplication'
            Remove = 'Remove-AdfsWebApiApplication'
        }

        $mockLdapAttributes = @(
            'mail'
            'sn'
        )

        $mockOutgoingClaimTypes = @(
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
        )

        $MSFT_AdfsLdapMappingProperties = @(
            @{
                LdapAttribute     = $mockLdapAttributes[0]
                OutgoingClaimType = $mockOutgoingClaimTypes[0]
            }
            @{
                LdapAttribute     = $mockLdapAttributes[1]
                OutgoingClaimType = $mockOutgoingClaimTypes[1]
            }
        )

        $mockTemplateName = 'LdapClaims'
        $mockRuleName = 'Test'

        $mockLdapMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $MSFT_AdfsLdapMappingProperties[0] -ClientOnly
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $MSFT_AdfsLdapMappingProperties[1] -ClientOnly
        )

        $mockMSFT_AdfsIssuanceTransformRuleProperties = @{
            TemplateName   = $mockTemplateName
            Name           = $mockRuleName
            AttributeStore = 'Active Directory'
            LdapMapping    = $mockLdapMapping
        }


        $mockIssuanceTransformRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
        )

        $mockLdapClaimsTransformRule = @(
            '@RuleTemplate = "{0}"' -f $mockTemplateName
            '@RuleName = "{0}"' -f $mockRuleName
            'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
            '=> issue(store = "Active Directory", types = ("{1}", "{2}"), query = ";{3},{4};{0}", param = c.Value);' -f `
                '{0}', $mockOutgoingClaimTypes[0], $mockOutgoingClaimTypes[1], $mockLdapAttributes[0], $mockLdapAttributes[1]
        ) | Out-String

        $mockResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                          = 'App1 Web Api'
            AccessControlPolicyName              = 'Permit everyone'
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = 'rule'
            DelegationAuthorizationRules         = 'rule'
            ImpersonationAuthorizationRules      = 'rule'
            IssuanceTransformRules               = $mockIssuanceTransformRules
            AdditionalAuthenticationRules        = 'rule'
            NotBeforeSkew                        = 5
            TokenLifetime                        = 90
            AlwaysRequireAuthentication          = $false
            AllowedClientTypes                   = 'Public'
            IssueOAuthRefreshTokensTo            = 'AllDevices'
            RefreshTokenProtectionEnabled        = $true
            RequestMFAFromClaimsProviders        = $true
            Ensure                               = 'Present'
        }

        $mockAbsentResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                          = $null
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = $null
            DelegationAuthorizationRules         = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceTransformRules               = $null
            AdditionalAuthenticationRules        = $null
            AccessControlPolicyName              = $null
            NotBeforeSkew                        = 0
            TokenLifetime                        = 0
            AlwaysRequireAuthentication          = $null
            AllowedClientTypes                   = 'None'
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            Ensure                               = 'Absent'
        }

        $mockMSFT_AdfsLdapMappingChangedProperties = @{
            LdapAttribute     = 'givenname'
            OutgoingClaimType = 'givenName'
        }

        $mockLdapChangedMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsLdapMappingChangedProperties -ClientOnly
        )

        $mockMSFT_AdfsIssuanceTransformChangedRuleProperties = @{
            TemplateName   = 'LdapClaims'
            Name           = 'Test2'
            AttributeStore = 'ActiveDirectory'
            LdapMapping    = $mockLdapChangedMapping
        }

        $mockIssuanceTransformChangedRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsIssuanceTransformChangedRuleProperties -ClientOnly
        )

        $mockChangedResource = @{
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338d'
            Description                          = 'App2 Web Api'
            AccessControlPolicyName              = 'changed'
            AllowedAuthenticationClassReferences = 'changed'
            ClaimsProviderName                   = 'changed'
            IssuanceAuthorizationRules           = 'changedrule'
            DelegationAuthorizationRules         = 'changedrule'
            ImpersonationAuthorizationRules      = 'changedrule'
            IssuanceTransformRules               = $mockIssuanceTransformChangedRules
            AdditionalAuthenticationRules        = 'changedrule'
            NotBeforeSkew                        = 10
            TokenLifetime                        = 180
            AlwaysRequireAuthentication          = $true
            AllowedClientTypes                   = 'Confidential'
            IssueOAuthRefreshTokensTo            = 'WorkplaceJoinedDevices'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
        }

        $mockChangedApplicationGroupIdentifier = 'AppGroup2'

        $mockGetTargetResourceResult = @{
            Name                                 = $mockResource.Name
            ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
            Identifier                           = $mockResource.Identifier
            Description                          = $mockResource.Description
            AccessControlPolicyName              = $mockResource.AccessControlPolicyName
            AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
            ClaimsProviderName                   = $mockResource.ClaimsProviderName
            IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
            DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
            ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
            IssuanceTransformRules               = $mockResource.IssuanceTransformRules
            AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
            NotBeforeSkew                        = $mockResource.NotBeforeSkew
            TokenLifetime                        = $mockResource.TokenLifetime
            AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
            AllowedClientTypes                   = $mockResource.AllowedClientTypes
            IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
            RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe "$Global:DSCResourceName\Get-TargetResource" -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name                       = $mockResource.Name
                    ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                    Identifier                 = $mockResource.Identifier
                }

                $mockGetResourceCommandResult = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    Description                          = $mockResource.Description
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceTransformRules               = $mockLdapClaimsTransformRule
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    TokenLifetime                        = $mockResource.TokenLifetime
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-Command
                Mock -CommandName Assert-AdfsService
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | ConvertTo-Json | Should -Be ($mockResource.$property | ConvertTo-Json)
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockAbsentResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-AdfsService" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }
        }

        Describe "$Global:DSCResourceName\Set-TargetResource" -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    Description                          = $mockResource.Description
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    TokenLifetime                        = $mockResource.TokenLifetime
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                }

                $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourcePresentParameters.Ensure = 'Present'

                $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceAbsentParameters.Ensure = 'Absent'

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName $ResourceCommand.Add
                Mock -CommandName $ResourceCommand.Remove
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {

                    Context 'When the Application Group Identifier has changed' {
                        BeforeAll {
                            $setTargetResourcePresentAgiChangedParameters = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourcePresentAgiChangedParameters.ApplicationGroupIdentifier = $mockChangedApplicationGroupIdentifier
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentAGIChangedParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentAgiChangedParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove `
                                -ParameterFilter { $TargetName -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Add `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentAgiChangedParameters.Name } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When the Application Group Identifier has not changed' {
                        foreach ($property in $mockChangedResource.Keys)
                        {
                            Context "When $property has changed" {
                                BeforeAll {
                                    $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                                    $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                                }

                                It 'Should not throw' {
                                    { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                                }

                                It 'Should call the correct mocks' {
                                    Assert-MockCalled -CommandName Get-TargetResource `
                                        -ParameterFilter { `
                                            $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName $ResourceCommand.Set `
                                        -ParameterFilter { `
                                            $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                                    Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                                }
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove `
                            -ParameterFilter { $TargetName -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                    }
                }
            }
        }

        Describe "$Global:DSCResourceName\Test-TargetResource" -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    Description                          = $mockResource.Description
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    TokenLifetime                        = $mockResource.TokenLifetime
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParameters = $testTargetResourcePresentParameters.Clone()
                                $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                            }

                            It 'Should return the desired result' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
                            }
                        }
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $true
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
