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
            @{Name="_Admin";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Service Accounts";Description="Service Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Privileged Users";Description="Admin User Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Admin";Name="Privileged Groups";Description="Admin User Accounts";ProtectedFromAccidentalDeletion=$false}
            @{Name="_Workstations";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Workstations";Name="Desktops";Description="Default Desktops";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Workstations";Name="Staging";Description="Staging Desktop OU Used During Builds";ProtectedFromAccidentalDeletion=$false}
            @{Name="_Standard";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="User Accounts";Description="Standard Users";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="Groups";Description="Standard Groups";ProtectedFromAccidentalDeletion=$false}
            @{Parent="OU=_Standard";Name="Distribution Lists";Description="Exchange Distribution Lists";ProtectedFromAccidentalDeletion=$false}
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
        Collections = @{
            DeviceCollections = @(
                    @{
                        BasicSettings = @{Name = "All Servers";Comment = "All Servers";LimitingCollectionName="All Systems";RefreshType=2}
                        Location = "Master Collections"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="All Servers";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "All Workstations";Comment = "All Workstations";LimitingCollectionName="All Systems";RefreshType=2}
                        Location = "Master Collections"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="All Workstations";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "All Workstations - Admin";Comment = "All workstations admin, to hide from technician";LimitingCollectionName="All Systems";RefreshType=2}
                        Location = "Master Collections"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="All Workstations - Admin";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "MC - CS - Workstation Prod";Comment = "Prod client settings for workstations";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Master Collections\MC - Client Settings"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        IncludeMembershipRules = @(
                            @{IncludeCollectionName="All Workstations"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "MC - CS - Workstation Test";Comment = "Test client settings for workstations";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Master Collections\MC - Client Settings"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "MC - CS - Server Prod";Comment = "Prod client settings for servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Master Collections\MC - Client Settings"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        IncludeMembershipRules = @(
                            @{IncludeCollectionName="All Servers"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "MC - CS - Server Test";Comment = "Test client settings for servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Master Collections\MC - Client Settings"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "MC - EP - Workstation Prod";Comment = "Endpoint Protection Policy for Prod Workstations";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Master Collections\MC - Endpoint Protection"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        IncludeMembershipRules = @(
                            @{IncludeCollectionName="All Servers"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "MC - EP - Workstation Test";Comment = "Endpoint Protection Policy for Test Workstations";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Master Collections\MC - Endpoint Protection"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "MC - EP - Server Prod";Comment = "Endpoint Protection Policy for PROD servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Master Collections\MC - Endpoint Protection"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        IncludeMembershipRules = @(
                            @{IncludeCollectionName="All Servers"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "MC - EP - Server Test";Comment = "Endpoint Protection Policy for Test Servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Master Collections\MC - Endpoint Protection"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Physical";Comment = "All physical servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="SRV - INV - Physical";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where SMS_R_System.ResourceId not in (select SMS_R_SYSTEM.ResourceID from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_R_System.IsVirtualMachine = 'True') and SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT%Server%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Virtual";Comment = "All virtual servers";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="SRV - INV - Virtual";QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where SMS_R_System.IsVirtualMachine = 'True' and SMS_R_System.OperatingSystemNameandVersion like 'Microsoft Windows NT%Server%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Windows 2008 and 2008 R2";Comment = "All servers with Windows 2008 or 2008 R2 operating system";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName="SRV - INV - Windows 2008 and 2008 R2";QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server 6.0%' or OperatingSystemNameandVersion like '%Server 6.1%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Windows 2012 and 2012 R2";Comment = "All servers with Windows 2012 or 2012 R2 operating system";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "SRV - INV - Windows 2012 and 2012 R2"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server 6.2%' or OperatingSystemNameandVersion like '%Server 6.3%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Windows 2003 and 2003 R2";Comment = "All servers with Windows 2003 or 2003 R2 operating system";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "SRV - INV - Windows 2003 and 2003 R2"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server 5.2%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "SRV - INV - Windows 2016";Comment = "All servers with Windows 2016";LimitingCollectionName="All Servers";RefreshType=2}
                        Location = "Servers\SRV - Inventory\SRV - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "SRV - INV - Windows 2016"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Server 10%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Windows 7";Comment = "All workstations with Windows 7 operating system";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Windows 7"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation 6.1%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Windows 8";Comment = "All workstations with Windows 8 operating system";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Windows 8"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation 6.2%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Windows 8.1";Comment = "All workstations with Windows 8.1 operating system";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Windows 8.1"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation 6.3%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Windows XP";Comment = "All workstations with Windows XP operating system";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Windows XP"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System   where OperatingSystemNameandVersion like '%Workstation 5.1%' or OperatingSystemNameandVersion like '%Workstation 5.2%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - SCCM Console";Comment = "All systems with SCCM console installed";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Software"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - SCCM Console"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_ADD_REMOVE_PROGRAMS on SMS_G_System_ADD_REMOVE_PROGRAMS.ResourceID = SMS_R_System.ResourceId where SMS_G_System_ADD_REMOVE_PROGRAMS.DisplayName like '%Configuration Manager Console%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Clients Version | 1710";Comment = "SCCM client version 1710";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Software"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Clients Version | 1710"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where SMS_R_System.ClientVersion like '5.00.8577.100%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Laptops | Dell";Comment = "All Dell Laptops";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Laptops | Dell"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%Dell%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Laptops | Lenovo";Comment = "All Lenovo Laptops";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Laptops | Lenovo"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%Lenovo%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Laptops | HP";Comment = "All HP Laptops";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Laptops | HP"; QueryExpression = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%HP%' or SMS_G_System_COMPUTER_SYSTEM.Manufacturer like '%Hewlett-Packard%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Microsoft Surface 4";Comment = "All Microsoft Surface 4 Laptops";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Hardware"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Microsoft Surface 4"; QueryExpression = "select SMS_R_System.ResourceId, SMS_R_System.ResourceType, SMS_R_System.Name, SMS_R_System.SMSUniqueIdentifier, SMS_R_System.ResourceDomainORWorkgroup, SMS_R_System.Client from SMS_R_System inner join SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceId = SMS_R_System.ResourceId where SMS_G_System_COMPUTER_SYSTEM.Model = 'Surface Pro 4'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - INV - Windows 10";Comment = "All workstations with Windows 10 operating system";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Inventory\WKS - Operating System"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        QueryMembershipRules = @(
                            @{RuleName = "WKS - INV - Windows 10"; QueryExpression = "select SMS_R_System.ResourceID,SMS_R_System.ResourceType,SMS_R_System.Name,SMS_R_System.SMSUniqueIdentifier,SMS_R_System.ResourceDomainORWorkgroup,SMS_R_System.Client from SMS_R_System where OperatingSystemNameandVersion like '%Workstation 10.%'"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - OSD - Windows 10 - PROD";Comment = "OSD Collection for Windows 10 deployment in production";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - OS Deployment"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "WKS - OSD - Windows 10 - TEST";Comment = "OSD collection to test deployment of Windows 10. Limited to admins only";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - OS Deployment"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SU - Exclusion";Comment = "Software Update collection to exclude computers from all Software Update collections. Manual Membership";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - Software Update"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SU - Pilot";Comment = "Software Update collection for Pilot group. Manual membership";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - Software Update"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        ExcludeMembershipRules = @(
                            @{ExcludeCollectionName="WKS - SU - Exclusion"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SU - TEST";Comment = "Software Update collection for test group. Manual membership";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - Software Update"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        ExcludeMembershipRules = @(
                            @{ExcludeCollectionName="WKS - SU - Exclusion"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SU - PROD";Comment = "Software Update collection for Production. All workstations";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - Software Update"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                        ExcludeMembershipRules = @(
                            @{ExcludeCollectionName="WKS - SU - Exclusion"}
                        )
                        IncludeMembershipRules = @(
                            @{IncludeCollectionName="All Workstations"}
                        )
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SD - Office 365 - PROD";Comment = "Collection for deployment of Office 365 production";LimitingCollectionName="All Workstations";RefreshType=2}
                        Location = "Workstations\WKS - Software Distribution"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
                    @{
                        BasicSettings = @{Name = "WKS - SD - Office 365 - TEST";Comment = "Test Collection for deployment of Office 365. Limited to admins only.";LimitingCollectionName="All Workstations - Admin";RefreshType=2}
                        Location = "Workstations\WKS - Software Distribution"
                        Schedule = @{RecurInterval="Days";RecurCount=7}
                    }
            )
        }
        WSUSProps = @{
            ContentDirectory='F:\WSUS'
            UpdateLanguages= @(
                'English'
            )
            DisabledProducts = @(
            )
            EnabledProducts = @(
                'Windows Server 2016'
                'Windows Server 2012 R2'
                'Windows 10'
                'Office 2010'
                'Office 2016'
            )
            EnabledProductFamilies = @(
            ) 
            DisabledClassifications = @(
                'Tools'
            )
            EnabledClassifications = @(
                'Critical Updates'    
                'Definition Updates'
                'Feature Packs'
                'Security Updates'
                'Service Packs'
                'Update Rollups'
                'Updates'
                'Upgrades'
            )
            Schedule = @{RecurInterval="Days";RecurCount=3}
        }
        DistributionPointProps = @(
             @{
                DistributionPointName = "SCCMLAB1-CM1.LABTEST.LOCAL"
                GeneralProps = @{ClientCommunicationType="HTTP"}
                PXEProps = @{EnablePxe=$True;PxeServerResponseDelaySeconds=0;AllowPxeResponse=$True;EnableUnknownComputerSupport=$True;UserDeviceAffinity="DoNotUse"}
                ValidationProps = @{EnableContentValidation=$True;Schedule = @{RecurInterval="Days";RecurCount=3}}
            }
        )
    }     
}

ConvertTo-Json $LabProperties -Depth 7 | Set-Content -Path $PSScriptRoot\SCCMProps.json
