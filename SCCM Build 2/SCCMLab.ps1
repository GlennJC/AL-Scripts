#This lab installs the SCCM role (1802). All required resources except the SQL Server ISO are downloaded during the deployment.

$VMPath = 'D:\AutomatedLab-VMs'
$2016GUI = 'Windows Server 2016 SERVERDATACENTER'
$LabName = "SCCMLAB1"
$vSwitch = 'SCCMLab'
$vlanid = '50'
$AddressSpace = '192.168.50.0/24'
$defaultGW = '192.168.50.252'
$mask = $AddressSpace.Split("/")[1]
$domain = 'labtest.local'
$DNSServers = '192.168.50.10'

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VMPath $VMPath -ReferenceDiskSizeInGB 80

Add-LabIsoImageDefinition -Name SQLServer2017 -Path $labsources\ISOs\SQLServer2017-x64-ENU.iso

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:OperatingSystem' = $2016GUI
    'Add-LabMachineDefinition:DomainName'      = $domain
    'Add-LabMachineDefinition:Ipv4Gateway'     = $defaultGW
}

#External Switch
$properties = @{ SwitchType = 'External'; AdapterName = 'EXT-04' ; ManagementAdapter = $true}
$MgtNIC = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address $AddressSpace -Ipv4Gateway $defaultGW -AccessVLANID $vlanid -ManagementAdapter $true
Add-LabVirtualNetworkDefinition -Name $vSwitch -HyperVProperties $properties -ManagementAdapter $MgtNIC

#Add-LabDomainDefinition -Name $domain -AdminUser Install -AdminPassword Password1

#Domain Controller
$roles = Get-LabMachineRoleDefinition -Role RootDC @{ DomainFunctionalLevel = 'Win2012R2'; ForestFunctionalLevel = 'Win2012R2' }
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.10/$mask -Ipv4Gateway $defaultGW `
    -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers
Add-LabMachineDefinition -Name "$($LabName)-DC1" -Memory 4GB -Roles $Roles -NetworkAdapter $netAdapter 

$sccmRole = Get-LabPostInstallationActivity -CustomRole SCCM -Properties @{
    SccmSiteCode          = "S01"
    SccmSiteName          = "Primary Site"
    SccmBinariesDirectory = "$labSources\SoftwarePackages\SCCM1802"
    SccmPreReqsDirectory  = "$labSources\SoftwarePackages\SCCMPreReqs1802"
    SccmInstallDirectory  = "D:\Program Files\Microsoft Configuration Manager"
    AdkDownloadPath       = "$labSources\SoftwarePackages\ADK1809"
    AdkWinPEDownloadPath  = "$labSources\SoftwarePackages\ADK1809WinPEAddons"
    SqlServerName         = "$($LabName)-DB1"
}

$Drives = @()
$Drives += (Add-LabDiskDefinition -Name CMDATA -DiskSizeInGb 200 -Label 'CMDATA' -DriveLetter D -PassThru).Name
$Drives += (Add-LabDiskDefinition -Name CMSOURCE -DiskSizeInGb 200 -Label 'CMSOURCE' -DriveLetter E -PassThru).Name
$Drives += (Add-LabDiskDefinition -Name WSUSDATA -DiskSizeInGb 200 -Label 'WSUSDATA' -DriveLetter F -PassThru).Name
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.20/$mask -Ipv4Gateway $defaultGW -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers

Add-LabMachineDefinition -Name "$($LabName)-CM1" -Memory 4GB -PostInstallationActivity $sccmRole -DiskName $Drives -NetworkAdapter $netAdapter

$sqlRole = Get-LabMachineRoleDefinition -Role SQLServer2017 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' }
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.21/$mask -Ipv4Gateway $defaultGW -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers
Add-LabMachineDefinition -Name "$($LabName)-DB1" -Memory 4GB -Roles $sqlRole -NetworkAdapter $netAdapter

Install-Lab

Restart-LabVM -Wait
######EXTRAS#######

$SccmServer = Get-LabVM -ComputerName "$($LabName)-CM1"


Install-LabWindowsFeature -ComputerName "$($LabName)-DC1" -FeatureName DHCP -IncludeAllSubFeature -IncludeManagementTools
Install-LabWindowsFeature -ComputerName "$($LabName)-CM1" -FeatureName RSAT-AD-Tools -IncludeAllSubFeature -IncludeManagementTools

Invoke-LabCommand -ActivityName 'Configure DHCP' -ComputerName "$($LabName)-DC1" -ScriptBlock {
    Import-Module DHCPServer
    Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias "Ethernet" | Out-Null
    Add-DHCPServerInDC -DNSName (Get-WmiObject Win32_ComputerSystem).Domain
    netsh dhcp add securitygroups
    $DHCPScopeSplat = @{
        Name          = 'Default Scope'
        StartRange    = '192.168.50.100'
        EndRange      = '192.168.50.150'
        SubnetMask    = '255.255.255.0'
        Description   = 'Default Scope for Clients'
        LeaseDuration = '0.08:00:00'
    }
    Add-DHCPServerv4Scope @DHCPScopeSplat

    $DHCPScopeOptionSplat = @{
        DnsServer = '192.168.50.10'
        Router    = '192.168.50.252'
        ScopeId   = '192.168.50.100'
        DnsDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    }
    Set-DhcpServerV4OptionValue @DHCPScopeOptionSplat

    #Fix the DNS Fowarder which is set to an Azure Address by default
    Set-DnsServerForwarder -IPAddress '192.168.10.254'
} 

Invoke-LabCommand -ActivityName 'Creating Active Directory OUs' -ComputerName "$($LabName)-DC1" -ScriptBlock {

    #Create OU Structure
    $ADRootDN = (Get-ADDomain).DistinguishedName
    New-ADOrganizationalUnit -Name "_Admin" -Path $ADRootDN -ProtectedFromAccidentalDeletion $True
    New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=_Admin, $ADRootDN" -ProtectedFromAccidentalDeletion $True -Description "Service Accounts"
    New-ADOrganizationalUnit -Name "Privileged Users" -Path "OU=_Admin, $ADRootDN" -ProtectedFromAccidentalDeletion $True -Description "Admin User Accounts"
    New-ADOrganizationalUnit -Name "Privileged Groups" -Path "OU=_Admin, $ADRootDN" -ProtectedFromAccidentalDeletion $True -Description "Admin Groups"
    
    New-ADOrganizationalUnit -Name "_Workstations" -Path $ADRootDN -ProtectedFromAccidentalDeletion $True
    New-ADOrganizationalUnit -Name "Desktops" -Path "OU=_Workstations, $ADRootDN" -ProtectedFromAccidentalDeletion $True -Description "Default Desktops"
    New-ADOrganizationalUnit -Name "Staging" -Path "OU=_Workstations, $ADRootDN" -ProtectedFromAccidentalDeletion $True -Description "Staging Desktop OU Used During Builds"

    #Domain Join Account, used during Task Sequences to add machines to the Domain
    New-ADUser -Name "svcDJ" -SamAccountName "svcDJ" -UserPrincipalName "svcDJ@$((Get-ADDomain).DNSRoot)" `
        -Description "SCCM Domain Join Account" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) `
        -Enabled $true -Path "OU=Service Accounts, OU=_Admin, $ADRootDN" -ChangePasswordAtLogon $False -PasswordNeverExpires $True   

        #Modified version of code from here:
    #https://scadminsblog.wordpress.com/2016/11/27/assigning-permissions-to-sccm-domain-join-account-with-powershell/

    Import-Module ActiveDirectory
    $ADRootDN = (Get-ADDomain).DistinguishedName
    $rootDSE = Get-ADRootDSE
    $SCCMDomainJoin = "svcDJ"
    $DNsToProcess = @(
        "OU=Staging, OU=_Workstations, $ADRootDN"
        "OU=Desktops, OU=_Workstations, $ADRootDN"
        "CN=Computers, $ADRootDN"
    )

    $guidmap = @{}
    Get-ADObject -SearchBase ($rootDSE.schemaNamingContext) -LDAPFilter `
        "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object {$guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID}

    # Create a hashtable to store the GUID value of each extended right in the forest
    $extendedrightsmap = @{}
    Get-ADObject -SearchBase ($rootDSE.configurationNamingContext) -LDAPFilter `
        "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid | ForEach-Object {$extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid}
    
    #Get the SID of the User Object
    $user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $SCCMDomainJoin).SID

    ForEach ($OU in $DNsToProcess) {
        #Get the OU We are going to change rights on
        $container = Get-ADObject -Identity ($OU)
        #Get the current ACL (we want to add to the existing rights)
        $ACL = Get-ACL -Path ("AD:\$($container.DistinguishedName)")
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "CreateChild", "Allow", $guidmap["computer"], "All"))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "DeleteChild", "Allow", $guidmap["computer"], "All"))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "ReadProperty", "Allow", "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "WriteProperty", "Allow", "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "ReadControl", "Allow", "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "WriteDacl", "Allow", "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ExtendedRightAccessRule $user, "Allow", $extendedrightsmap["Reset Password"], "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ExtendedRightAccessRule $user, "Allow", $extendedrightsmap["Change Password"], "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "Self", "Allow", $extendedrightsmap["Validated write to DNS host name"], "Descendents", $guidmap["computer"]))
        $ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user, "Self", "Allow", $extendedrightsmap["Validated write to service principal name"], "Descendents", $guidmap["computer"]))
        #Write the ACL back with the new rights added
        Set-ACL -AclObject $ACL -Path ("AD:\$($container.DistinguishedName)")
    }   
}

Invoke-LabCommand -ActivityName 'Install and Configure WSUS' -ComputerName "$($LabName)-CM1" -ScriptBlock {
    #Install WSUS Features (will use Existing SQL Server)
    Install-WindowsFeature -Name UpdateServices-Services, UpdateServices-DB -IncludeManagementTools

    #Create A Directory on the SCCM Server to hold the WSUS Content
    New-Item -Path F:\WSUS -ItemType Directory -Force

    #Configure WSUS to tell it where the updates should be stored and to use SQL for its database
    & "C:\Program Files\Update Services\Tools\wsusutil.exe" postinstall SQL_INSTANCE_NAME="SCCMLAB1-DB1" CONTENT_DIR=F:\WSUS

    #Force an update of the SCCM Products and Categories (defualt list is heavily out of date)
    $WSUSServer = Get-WSUSServer
    $WSUSConfig = $WSUSServer.GetConfiguration()
    Set-WsusServerSynchronization -SyncFromMU
    $WSUSConfig.AllUpdateLanguagesEnabled = $false           
    $WSUSConfig.SetEnabledUpdateLanguages('en')           
    $WSUSConfig.Save()
    $WSUSSubscription = $WSUSServer.GetSubscription()
    $WSUSSubscription.StartSynchronizationForCategoryOnly()

    While ($WSUSSubscription.GetSynchronizationStatus() -ne 'NotProcessing') {
        Start-Sleep -Seconds 5
    }
} 

#Add Network Access Account in SCCM
Invoke-LabCommand -ActivityName 'Configure SCCM Accounts' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    param (
        [string]$SCCMSiteCode
    )

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    $NetBIOSDomainName = (Get-WmiObject -Class Win32_NTDomain).DomainName
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    $ADRootDN = (Get-ADDomain).DistinguishedName
    #region Network Access Account
    #Network Access Account, used to access content from WinPE during deployment
    $NAASvc = 'svcNAA'
    $NAA = "{0}\{1}" -f $NetBIOSDomainName[1].ToUpper(), $NAASvc
    $NAAPwd = ConvertTo-SecureString "Password123" -AsPlainText -Force

    New-ADUser -Name $AASvc -SamAccountName $NAASvc -UserPrincipalName "$NAASvc@$((Get-ADDomain).DNSRoot)" `
        -Description "SCCM Network Access Account" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) `
        -Enabled $true -Path "OU=Service Accounts, OU=_Admin, $ADRootDN" -ChangePasswordAtLogon $False -PasswordNeverExpires $True   

    #Create the Network Access Account in SCCM
    New-CMAccount -Name $NAA -Password $NAAPwd -Sitecode $SiteCode.Name
    #Set this account as the Network Access Account
    Set-CMSoftwareDistributionComponent -Sitecode $SiteCode.Name -NetworkAccessAccountName $NAA
    #endregion Network Access Account

    #region Client Push Account
    $Pushsvc = 'svcPush'
    $PushAcct = "{0}\{1}" -f $NetBIOSDomainName[1].ToUpper(), $Pushsvc
    $PushPass = ConvertTo-SecureString "Password123" -AsPlainText -Force

    $PushADAccountSplat = @{
        Name = $Pushsvc
        SamAccountName = $Pushsvc
        UserPrincipalName = "$Pushsvc@$((Get-ADDomain).DNSRoot)"
        Description = "SCCM Client Push Access Account"
        AccountPassword = $PushPass
        Enabled = $true
        Path = "OU=Service Accounts, OU=_Admin, $($ADRootDN)"
        ChangePasswordAtLogon = $False
        PasswordNeverExpires = $True 
    }

    New-ADUser @PushADAccountSplat -PassThru | Add-ADPrincipalGroupMembership -MemberOf "Domain Admins"

    New-CMAccount -Name $PushAcct -Password $PushPass -Sitecode $SiteCode.Name

    $ClientPushSplat = @{
        EnableAutomaticClientPushInstallation = $true
        EnableSystemTypeConfigurationManager = $true
        InstallClientToDomainController = $true 
        ChosenAccount = $PushAcct
        SiteCode = $SiteCode  
    }
    Set-CMClientPushInstallation @ClientPushSplat

    #endregion Client Push Account

} -ArgumentList 'S01'

#Get the Root OU Container
Invoke-LabCommand -ActivityName 'Configure SCCM Discovery and Boundaries' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    param (
        [string]$SccmSiteCode,
        $NetworkParams
    )

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    $IPRange = '{0}-{1}' -f $NetworkParams.FirstUsable, $NetworkParams.LastUsable
    $BoundaryName = '{0} Boundary' -f $NetworkParams.Network
    New-CMBoundary -DisplayName $BoundaryName -BoundaryType IPRange -Value $IPRange
    $BoundaryGroupName = '{0} Boundary Group' -f $NetworkParams.Network
    New-CMBoundaryGroup -Name $BoundaryGroupName -AddSiteSystemServerNames $ProviderMachineName -DefaultSiteCode $SiteCode
    Add-CMBoundaryToGroup -BoundaryName $BoundaryName -BoundaryGroupName $BoundaryGroupName 

    #Set up a common schedule for discovery. This will perform a discovery 1 time per day forever from todays date at midnight
    $Schedule = New-CMSchedule -RecurInterval Days -Start (Get-Date -Format "yyyy/MM/dd 00:00:00") -RecurCount 1

    #set the common discovery parameters used by all discovery cmdlets
    $CmDiscoverySplatCommon = @{
        SiteCode = $SiteCode
        Enabled = $true
        EnableDeltaDiscovery = $true
        DeltaDiscoveryMins = 30
    }

    #specific settings for the AD + User Discovery
    $CmDiscoverySystemSplat = @{
        ActiveDirectoryContainer = "LDAP://$((Get-ADDomain).DistinguishedName)"
        Recursive = $true
    }
    Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -PollingSchedule $Schedule @cmDiscoverySplatCommon @CmDiscoverySystemSplat
    Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -PollingSchedule $Schedule @cmDiscoverySplatCommon @CmDiscoverySystemSplat

    #Specific settings for the Group Discovery
    $CMGroupDiscoveryScopeSplat = @{
        LdapLocation = "LDAP://$((Get-ADDomain).DistinguishedName)"
        Name = 'AD Group Discovery'
        SiteCode = $SiteCode
        RecursiveSearch = $true
    }
    #Create a search scope for groups
    $GroupScope = New-CMADGroupDiscoveryScope @CMGroupDiscoveryScopeSplat
    $CMDiscoveryGroupSplat = @{
        DiscoverDistributionGroupMembership = $true
    }
    Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -AddGroupDiscoveryScope $GroupScope -PollingSchedule $Schedule @cmDiscoverySplatCommon @CMDiscoveryGroupSplat

} -ArgumentList 'S01',$SccmServer.IpAddress


## Enable PXE on Distribution Point

## Enable MDT Integration in SCCM

## Create Boot images and Distribute

#Add Image Source for Windows 10
# Dismount-LabIsoImage -ComputerName "$($LabName)-CM1"
# $ISOPath = Mount-LabIsoImage -ComputerName "$($LabName)-CM1" -IsoPath (Get-LabAvailableOperatingSystem -NoDisplay| Where-Object {$_.OperatingSystemImageName -eq 'Windows 10 Enterprise' -and $_.Version -eq '10.0.17134.1'}).ISOPath -PassThru

# Invoke-LabCommand -ActivityName 'Copy Windows 10 Source' -ComputerName "$($LabName)-CM1" -ScriptBlock {
#     param
#     (
#         [string]$SourceDrive
#     )

#     New-Item -Path 'D:\ContentLibrary\OperatingSystems\Windows10\1803' -ItemType Directory -Force
#     Copy-Item -Path $($SourceDrive + '*') -Destination 'D:\ContentLibrary\OperatingSystems\Windows10\1803\' -Recurse
# } -ArgumentList $($ISOPath.DriveLetter + "\")

# Dismount-LabIsoImage -ComputerName "$($LabName)-CM1"

Show-LabDeploymentSummary -Detailed


