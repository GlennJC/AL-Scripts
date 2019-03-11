$LabProperties = @{
    LabProps = @{
        LabName = 'SCCMLAB1'
        VMPath = 'D:\AutomatedLab-VMs'
        ServerOS = 'Windows Server 2016 SERVERDATACENTER'
        ReferenceDiskSize = 80   
    }
    SwitchProps = @{
        SwitchType = 'External'
        AdapterName = 'EXT-04'
        ManagementAdapter = $true
        vSwitchName = 'SCCMLab'
        vLANid = '50'
    }
    NetworkProps = @{
        AddressSpace = '192.168.50.0'
        DefaultGW = '192.168.50.252'
        Netmask = '24'
        DNSServers = '192.168.50.10'
        DNSServerFowarder = '192.168.10.254'
        DHCPScope = @{
           Name          = 'Default Scope'
           StartRange    = '192.168.50.100'
           EndRange      = '192.168.50.150'
           SubnetMask    = '255.255.255.0'
           Description   = 'Default Scope for Clients'
           LeaseDuration = '0.08:00:00'
        }
        DHCPScopeOptions = @{
            DnsServer = '192.168.50.10'
            Router    = '192.168.50.252'
            ScopeId   = '192.168.50.100'
            DNSDomain = 'labtest.local'
            }
    }
    ADProps = @{
        DomainName = 'labtest.local'
        DomainFunctionalLevel = 'Win2012R2'
        ForestFunctionalLevel = 'Win2012R2'
        OUStructure = @(
            @{Name="_Admin"}
            @{Name="Service Accounts";Parent="OU=_Admin";Description="Service Accounts";Protected=$true}
            @{Name="Privileged Users";Parent="OU=_Admin";Description="Admin User Accounts";Protected=$true}
            @{Name="Privileged Groups";Parent="OU=_Admin";Description="Admin User Accounts";Protected=$true}
            @{Name="_Workstations"}
            @{Name="Desktops";Parent="OU=_Workstations";Description="Default Desktops"}
            @{Name="Staging";Parent="OU=_Workstations";Description="Staging Desktop OU Used During Builds"}
            @{Name="_Standard"}
            @{Name="User Accounts";Parent="OU=_Standard";Description="Standard Users"}
            @{Name="Groups";Parent="OU=_Standard";Description="Standard Groups"}
            @{Name="Distribution Lists";Parent="OU=_Standard";Description="Exchange Distribution Lists"}
        )
    }
    SCCMInstallProps = @{
        SccmSiteCode          = "S01"
        SccmSiteName          = "Primary Site"
        SccmBinariesDirectory = "$labSources\SoftwarePackages\SCCM1802"
        SccmPreReqsDirectory  = "$labSources\SoftwarePackages\SCCMPreReqs1802"
        SccmInstallDirectory  = "D:\Program Files\Microsoft Configuration Manager"
        AdkDownloadPath       = "$labSources\SoftwarePackages\ADK1809"
        AdkWinPEDownloadPath  = "$labSources\SoftwarePackages\ADK1809WinPEAddons"
        SqlServerName         = "$($LabName)-DB1"
    }
    SccmConfigProps = @{
        ServiceAccounts = @(
            @{Role="DJ";Name="svcDJ";SamAccountName="svcDJ";UserPrincipalName="svcDJ";Password="Password123";Description="SCCM Domain Join Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
            @{Role="CP";Name="svcPush";SamAccountName="svcPush";UserPrincipalName="svcPush";Password="Password123";Description="SCCM Client Push Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
            @{Role="NA";Name="svcNAA";SamAccountName="svcNAA";UserPrincipalName="svcNAA";Password="Password123";Description="SCCM Network Access Account";Enabled=$true;Path="OU=Service Accounts, OU=_Admin";ChangePasswordAtLogon=$False;PasswordNeverExpires=$True}
        )
        DomainJoinAccountOUs = @(
            @{OUName="OU=Desktops,OU=_Workstations"}
            @{OUName="OU=Staging,OU=_Workstations"}
            @{OUName="CN=Computers"}
        )
        WSUSProps = @{
            ContentDirectory='F:\WSUS'
            UpdateLanguages= @(
                'en'
            )
            DisabledProducts = @(
                'Windows'
                'Office'
                'Language Packs'
            )
            EnabledProducts = @(
                'Windows Server 2016'
                'Windows 10'
                'Office 2016'
            )
        }
        BoundaryGroups = @(
            @{Name="Default Boundary Group";SiteCode="S01"}
        )
        SiteBoundaries = @(
            @{Name="192.168.50.0 Boundary";IPRange="192.168.50.1-192.168.50.254";MemberOfBoundaryGroupName="Default Boundary Group"}
            @{Name="192.168.51.0 Boundary";IPRange="192.168.51.1-192.168.51.254";MemberOfBoundaryGroupName="Default Boundary Group"}
            @{Name="192.168.52.0 Boundary";IPRange="192.168.52.1-192.168.52.254";MemberOfBoundaryGroupName="Default Boundary Group"}
        )
        DiscoveryMethods = @{
            ActiveDirectorySystemDiscovery = @{
                Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;ActiveDirectoryContainer="LDAP://DC=LABTEST,DC=LOCAL";Recursive=$true}
                Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
            }
            ActiveDirectoryUserDiscovery = @{
                Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;ActiveDirectoryContainer="LDAP://DC=LABTEST,DC=LOCAL";Recursive=$true}
                Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
            }
            ActiveDirectoryGroupDiscovery = @{
                Settings = @{SiteCode = "S01";Enabled=$true;EnableDeltaDiscovery=$true;DeltaDiscoveryMins=30;DiscoverDistributionGroupMembership = $true}
                Scope = @{ Name = 'AD Group Discovery';SiteCode = "S01";RecursiveSearch = $true;LdapLocation="LDAP://DC=LABTEST,DC=LOCAL"}
                Schedule = @{RecurInterval="Days";RecurCount=1;Start="01/01/2001"}
            }
            HeartbeatDiscovery = @{
                Settings = @{SiteCode = "S01";Enabled=$true}
                Schedule = @{RecurInterval="Days";RecurCount=7}
            }
        }
    }     
}
ConvertTo-Json $LabProperties -Depth 4 | Set-Content -Path C:\LabSources\MyScripts\SCCMProps.json
