#This lab installs the SCCM role (1802). All required resources except the SQL Server ISO are downloaded during the deployment.

##Helper Functions
function ConvertTo-JSONToHash {
    param(
        $root
    )
    $hash = @{}
    $keys = $root | Get-Member -MemberType NoteProperty | Select-Object -exp Name
    $keys | ForEach-Object {
        $key = $_
        $obj = $root.$($_)
        if ($obj -match "@{") {
            $nesthash = ConvertTo-JSONToHash $obj
            $hash.add($key, $nesthash)
        }
        else {
            $hash.add($key, $obj)
        }
    }
    return $hash
}

#Majority of settings are within this config file.
#Note: much of the content in this file is used for hastable splatting, so the names of variables is important and should NOT be changed
#this PSObject to hastable conversiopn either occurs inline, or using the ConvertTo-JSONToHash function
$ConfigFile = Get-Content -Path C:\LabSources\MyScripts\SCCMProps.json | ConvertFrom-Json 

#$VMPath = 'D:\AutomatedLab-VMs'
#$2016GUI = 'Windows Server 2016 SERVERDATACENTER'
#$LabName = "SCCMLAB1"
#$vSwitch = 'SCCMLab'
#$vlanid = '50'
#$AddressSpace = '192.168.50.0/24'
#$defaultGW = '192.168.50.252'
#$mask = $AddressSpace.Split("/")[1]
#$domain = 'labtest.local'
#$DNSServers = '192.168.50.10'

$LabName = $ConfigFile.LabProps.LabName
$DefaultGW = $ConfigFile.NetworkProps.DefaultGW
$vSwitch = $ConfigFile.SwitchProps.vSwitchName
$vLANid = $ConfigFile.SwitchProps.vLANid
$AddressSpace = "{0}/{1}" -f $ConfigFile.NetworkProps.AddressSpace, $ConfigFile.NetworkProps.NetMask
$Mask = $ConfigFile.NetworkProps.NetMask
$DNSServers = $ConfigFile.NetworkProps.DNSServers

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VMPath $ConfigFile.LabProps.VMPath -ReferenceDiskSizeInGB $ConfigFile.LabProps.ReferenceDiskSize

Add-LabIsoImageDefinition -Name SQLServer2017 -Path $labsources\ISOs\SQLServer2017-x64-ENU.iso

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:OperatingSystem' = $ConfigFile.LabProps.ServerOS
    'Add-LabMachineDefinition:DomainName'      = $ConfigFile.ADProps.DomainName
    'Add-LabMachineDefinition:Ipv4Gateway'     = $ConfigFile.NetworkProps.DefaultGW
}

#External Switch
$MgtNetworkDefinitionSplat = @{
    VirtualSwitch     = $vSwitch
    Ipv4Address       = $AddressSpace
    Ipv4Gateway       = $defaultGW
    AccessVLANID      = $vlanid
    ManagementAdapter = $ConfigFile.SwitchProps.ManagementAdapter    
}
$MgtNIC = New-LabNetworkAdapterDefinition @MgtNetworkDefinitionSplat
$properties = @{ SwitchType = $ConfigFile.SwitchProps.SwitchType; AdapterName = $ConfigFile.SwitchProps.AdapterName ; ManagementAdapter = $true}
Add-LabVirtualNetworkDefinition -Name $vSwitch -HyperVProperties $properties -ManagementAdapter $MgtNIC

#Domain Controller
$roles = Get-LabMachineRoleDefinition -Role RootDC @{ DomainFunctionalLevel = $ConfigFile.ADProps.DomainFunctionalLevel; ForestFunctionalLevel = $ConfigFile.ADProps.ForestFunctionalLevel }
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.10/$mask -Ipv4Gateway $defaultGW `
    -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers
Add-LabMachineDefinition -Name "$($LabName)-DC1" -Memory 2GB -Roles $Roles -NetworkAdapter $netAdapter -Processors 2

$sccmRole = Get-LabPostInstallationActivity -CustomRole SCCM -Properties @{
    SccmSiteCode          = $ConfigFile.SCCMInstallProps.SccmSiteCode
    SccmSiteName          = $ConfigFile.SCCMInstallProps.SccmSiteName
    SccmBinariesDirectory = "$labSources\SoftwarePackages\SCCM1802"
    SccmPreReqsDirectory  = "$labSources\SoftwarePackages\SCCMPreReqs1802"
    SccmInstallDirectory  = $ConfigFile.SCCMInstallProps.SccmInstallDirectory
    AdkDownloadPath       = "$labSources\SoftwarePackages\ADK1809"
    AdkWinPEDownloadPath  = "$labSources\SoftwarePackages\ADK1809WinPEAddons"
    SqlServerName         = "$($LabName)-DB1"
}

$Drives = @()
$Drives += (Add-LabDiskDefinition -Name CMDATA -DiskSizeInGb 200 -Label 'CMDATA' -DriveLetter D -PassThru).Name
$Drives += (Add-LabDiskDefinition -Name CMSOURCE -DiskSizeInGb 200 -Label 'CMSOURCE' -DriveLetter E -PassThru).Name
$Drives += (Add-LabDiskDefinition -Name WSUSDATA -DiskSizeInGb 200 -Label 'WSUSDATA' -DriveLetter F -PassThru).Name
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.20/$mask -Ipv4Gateway $defaultGW -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers

Add-LabMachineDefinition -Name "$($LabName)-CM1" -Memory 6GB -Processors 4 -PostInstallationActivity $sccmRole -DiskName $Drives -NetworkAdapter $netAdapter

$sqlRole = Get-LabMachineRoleDefinition -Role SQLServer2017 -Properties @{ Collation = 'SQL_Latin1_General_CP1_CI_AS' }
$netAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $vSwitch -Ipv4Address 192.168.50.21/$mask -Ipv4Gateway $defaultGW -AccessVLANID $vlanid -InterfaceName $vSwitch -Ipv4DNSServers $DNSServers
Add-LabMachineDefinition -Name "$($LabName)-DB1" -Memory 4GB -Processors 4 -Roles $sqlRole -NetworkAdapter $netAdapter

Install-Lab

Restart-LabVM -ComputerName (Get-LabVM -All) -Wait
######EXTRAS#######

$SccmServer = Get-LabVM -ComputerName "$($LabName)-CM1"

Install-LabWindowsFeature -ComputerName "$($LabName)-DC1" -FeatureName DHCP -IncludeAllSubFeature -IncludeManagementTools
Install-LabWindowsFeature -ComputerName "$($LabName)-CM1" -FeatureName RSAT-AD-Tools -IncludeAllSubFeature -IncludeManagementTools


$ScopeDetails = ConvertTo-JSONToHash -root $ConfigFile.NetworkProps.DHCPScope
$ScopeOptions = ConvertTo-JSONToHash -root $ConfigFile.NetworkProps.DHCPScopeOptions

Invoke-LabCommand -ActivityName 'Configure DHCP' -ComputerName "$($LabName)-DC1" -ScriptBlock {

    param (
        [Hashtable]$ScopeDetails,
        [HashTable]$ScopeOptions,
        [string]$DNSServerFowarder
    )
    Import-Module DHCPServer
    #Bind the Ethernet Adapter to listen to DHCP Requests
    Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias "Ethernet" | Out-Null

    #If the DHCP Server hasnt been Authorised in AD, Authorise it
    if (-not (Get-DHCPServerInDC | Where-Object {$_.IpAddress -eq (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet').IPv4Address})) {
        Add-DHCPServerInDC -DNSName (Get-WmiObject Win32_ComputerSystem).Domain
        netsh dhcp add securitygroups
    }
    
    #If the Scope doesnt exist, create it
    if (-not (Get-DHCPServerv4Scope | Where-Object {$_.Name -eq $ScopeDetails.Name})) {
        Add-DHCPServerv4Scope @ScopeDetails
        Set-DhcpServerV4OptionValue @ScopeOptions
    }
    
    #Fix the DNS Server Fowarder Address
    Set-DnsServerForwarder -IPAddress $DNSServerFowarder
} -ArgumentList $ScopeDetails, $ScopeOptions, $ConfigFile.NetworkProps.DNSServerFowarder

Invoke-LabCommand -ActivityName 'Creating Active Directory OUs' -ComputerName "$($LabName)-DC1" -ScriptBlock {

    param (
        [Object[]]$OUStructure
    )
    function ConvertTo-PSObjectToHash {
        param (
            [Object]$Obj
        )
    
        $Hash = @{}
        foreach ( $property in $Obj.psobject.properties.name ) {
            $Hash[$property] = $Obj.$property
        }
        [HashTable]$Hash
    }

    #Create OU Structure based on the incoming array
    $ADRootDN = (Get-ADDomain).DistinguishedName

    foreach  ($OU in $OUStructure)
    {
        if (-not $OU.Parent -or $OU.Parent -eq '') {$ParentOU = $ADRootDN} else {$ParentOU = $('{0}, {1}' -f $OU.Parent, $ADRootDN)}

        #Copy the object, and remove the Parent parameter
        $TempOU = $OU.psobject.copy()
        $TempOU.PSObject.Properties.Remove('Parent')
        #Convert this to a hastable for splatting
        $OUSplat = ConvertTo-PSObjectToHash -obj $TempOU

        try {
            Get-ADOrganizationalUnit -Identity $('OU={0},{1}' -f $OU.Name, $ParentOU)
        }
        catch {
            New-ADOrganizationalUnit -Path $ParentOU @OUSplat
        }

    }

} -ArgumentList (,$ConfigFile.ADProps.OUStructure)

Invoke-LabCommand -ActivityName 'Creating Service Accounts' -ComputerName "$($LabName)-DC1" -ScriptBlock {

    param (
        [Object[]]$ServiceAccounts,
        [Object[]]$DNsToProcess
    )

    Import-Module ActiveDirectory

    $ADRootDN = (Get-ADDomain).DistinguishedName
    $ADRootDNS = (Get-ADDomain).DNSRoot
    $rootDSE = Get-ADRootDSE

    foreach ($Acct in $ServiceAccounts) {
        $TempAcct = $Acct.psobject.copy()
        #Save the role as we will do things with it, but the AD cmdlet will have an issue with the property being present, so it will be removed shortly
        $AccountRole = $TempAcct.Role
        $AccountPassword = $TempAcct.Password
        #Fix the UPN and OU Patch for the new object
        $UPN = "$($TempAcct.UserPrincipalName)@$ADRootDNS"
        $OUPath = "$($TempAcct.Path),$ADRootDN"

        #Remove and replace the entries we have tweaked
        $TempAcct.psobject.properties.remove('Role')
        $TempAcct.psobject.properties.remove('Path')
        $TempAcct.psobject.properties.remove('Password')
        $TempAcct.psobject.properties.remove('UserPrincipalName')
        $TempAcct | Add-Member -MemberType NoteProperty -Name 'Path' -Value $OUPath -Force
        $TempAcct | Add-Member -MemberType NoteProperty -Name 'UserPrincipalName' -Value $UPN -Force
        $TempAcct | Add-Member -MemberType NoteProperty -Name 'AccountPassword' -Value (ConvertTo-SecureString $AccountPassword -AsPlainText -Force) -Force

        #Convert this object to a hashtable so we can splat it
        $AccountHash = @{}
        foreach ( $property in $TempAcct.psobject.properties.name ) {
            $AccountHash[$property] = $TempAcct.$property
        }

        #Create the Account
        New-ADUser @AccountHash

        #See if there is anything additional to do based on the account role. Note this only handles AD-Level activities
        #the SCCM Config actions will perform SCCM specific configs
        switch ($AccountRole) {
            'DJ' {
                #Domain Join Account

                #Grant the account control over computer objects in the defined OU's so machines can be added and moved within the domain
                #during the task sequence build

                #Modified Version of code from here
                #https://scadminsblog.wordpress.com/2016/11/27/assigning-permissions-to-sccm-domain-join-account-with-powershell/
            
                $guidmap = @{}
                Get-ADObject -SearchBase ($rootDSE.schemaNamingContext) -LDAPFilter "(schemaidguid=*)" `
                    -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object {$guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID}

                # Create a hashtable to store the GUID value of each extended right in the forest
                $extendedrightsmap = @{}
                Get-ADObject -SearchBase ($rootDSE.configurationNamingContext) -LDAPFilter `
                    "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid | ForEach-Object {$extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid}
    
                #Get the SID of the User Object
                $user = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $TempAcct.SamAccountName).SID

                ForEach ($OU in $DNsToProcess) {

                    $FullOUPath = "$($OU.OUName),$ADRootDN"
                    #Get the OU We are going to change rights on
                    $container = Get-ADObject -Identity ($FullOUPath)
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
            'CP' {
                #Client Push Account
                #To deploy client agents to domain controllers, the account needs to be a member of Domain Admins
                Get-ADUser $TempAcct.SamAccountName | Add-ADPrincipalGroupMembership -MemberOf "Domain Admins"
            }
            'NA' {
                #Network Access Account

                #Nothing special at this point
            }
        } 
    }
} -ArgumentList ($ConfigFile.SccmConfigProps.ServiceAccounts), ($ConfigFile.SccmConfigProps.DomainJoinAccountOUs)

Invoke-LabCommand -ActivityName 'Installing and Configuring WSUS' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    Param (
        [string]$ContentDirectory
    )

    #THis function does the initial configuration of WSUS for SCCM. All other configuration is done from within SCCM as part of the Software Update Role
    #Install WSUS Features (will use Existing SQL Server).
    Install-WindowsFeature -Name UpdateServices-Services, UpdateServices-DB -IncludeManagementTools

    #Create A Directory on the SCCM Server to hold the WSUS Content
    New-Item -Path $ContentDirectory -ItemType Directory -Force

    #Configure WSUS to tell it where the updates should be stored and to use SQL for its database
    & "C:\Program Files\Update Services\Tools\wsusutil.exe" postinstall SQL_INSTANCE_NAME="SCCMLAB1-DB1" CONTENT_DIR=$($ContentDirectory)

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
} -ArgumentList $ConfigFile.SccmConfigProps.WSUSProps.ContentDirectory

Invoke-LabCommand -ActivityName 'Configuring SCCM Accounts' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    param (
        [Object[]]$ServiceAccounts,
        [string]$SCCMSiteCode
    )

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    $NetBIOSDomainName = (Get-WmiObject -Class Win32_NTDomain).DomainName
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    foreach ($Acct in $ServiceAccounts) {

        switch ($Acct.Role) {
            'DJ' {
                #Nothing Extra to do at this stage
            }
            'NA' {
                $NAAPwd = (ConvertTo-SecureString $Acct.Password -AsPlainText -Force)
                $NAA = "{0}\{1}" -f $NetBIOSDomainName[1].ToUpper(), $Acct.SamAccountName
                New-CMAccount -Name $NAA -Password $NAAPwd -Sitecode $SiteCode.Name
                #Set this account as the Network Access Account
                Set-CMSoftwareDistributionComponent -Sitecode $SiteCode.Name -NetworkAccessAccountName $NAA
            }
            'CP' {
                $PushPass = (ConvertTo-SecureString $Acct.Password -AsPlainText -Force)
                $PushAcct = "{0}\{1}" -f $NetBIOSDomainName[1].ToUpper(), $Acct.SamAccountName
                New-CMAccount -Name $PushAcct -Password $PushPass -Sitecode $SiteCode.Name
                $ClientPushSplat = @{
                    EnableAutomaticClientPushInstallation = $true
                    EnableSystemTypeConfigurationManager  = $true
                    InstallClientToDomainController       = $true 
                    ChosenAccount                         = $PushAcct
                    SiteCode                              = $SiteCode.Name  
                }
                Set-CMClientPushInstallation @ClientPushSplat
            }
        }
    }
} -ArgumentList ($ConfigFile.SccmConfigProps.ServiceAccounts), $ConfigFile.SCCMInstallProps.SccmSiteCode

Invoke-LabCommand -ActivityName 'Configuring SCCM Boundaries' -ComputerName "$($LabName)-CM1" -ScriptBlock {
    param (
        [string]$SccmSiteCode,
        [Object[]]$Boundaries,
        [Object[]]$BoundaryGroups
    )

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    #Assume that the SCCM Server itself will service the Boundary Groups that are created
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    foreach ($BoundaryGroup in $BoundaryGroups) {
        New-CMBoundaryGroup -Name $BoundaryGroup.Name -AddSiteSystemServerNames $ProviderMachineName -DefaultSiteCode $BoundaryGroup.SiteCode
    }
    
    foreach ($Boundary in $Boundaries) {
        New-CMBoundary -DisplayName $Boundary.Name -BoundaryType IPRange -Value $Boundary.IPRange
        Add-CMBoundaryToGroup -BoundaryName $Boundary.Name -BoundaryGroupName $Boundary.MemberOfBoundaryGroupName
    }

} -ArgumentList $ConfigFile.SCCMInstallProps.SccmSiteCode, ($ConfigFile.SccmConfigProps.SiteBoundaries), ($ConfigFile.SccmConfigProps.BoundaryGroups)

Invoke-LabCommand -ActivityName 'Configuring SCCM Discovery Methods' -ComputerName "$($LabName)-CM1" -ScriptBlock {
    #Additional Parameters which can be entered into the Config File for discovery methods are located here:
    #https://docs.microsoft.com/en-us/powershell/module/configurationmanager/set-cmdiscoverymethod?view=sccm-ps
    param (
        [string]$SccmSiteCode,
        [Object[]]$DiscoveryMethods
    )

    function ConvertTo-PSObjectToHash {
        param ( [Object]$Obj )
        $Hash = @{}
        foreach ( $property in $Obj.psobject.properties.name ) {$Hash[$property] = $Obj.$property}
        [HashTable]$Hash
    }
     
    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    #Assume that the SCCM Server itself will service the Boundary Groups that are created
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    if ($DiscoveryMethods.ActiveDirectorySystemDiscovery) {
        #Grab the standard Settings
        $SettingsSplat = ConvertTo-PSObjectToHash -obj $DiscoveryMethods.ActiveDirectorySystemDiscovery.Settings
        #Grab the Schedule Settings
        $TempSchedule = $DiscoveryMethods.ActiveDirectorySystemDiscovery.Schedule.psobject.copy()
        #Convert the passed in Date/Time to the correct Format, and replace the Member Variable
        $TempSchedule | Add-Member -MemberType NoteProperty -Name 'Start' -Value (Get-Date -Date $TempSchedule.Start -Format "yyyy/MM/dd 00:00:00") -Force
        #Convert this to a hastable for splatting
        $ScheduleSplat = ConvertTo-PSObjectToHash -obj $TempSchedule
        #Create a new Schedule
        $Schedule = New-CMSchedule @ScheduleSplat
        #Set the Discovery Method with the new Schedule
        Set-CMDiscoveryMethod -ActiveDirectorySystemDiscovery -PollingSchedule $Schedule @SettingsSplat
    }

    if ($DiscoveryMethods.ActiveDirectoryUserDiscovery) {
        #Grab the standard Settings
        $SettingsSplat = ConvertTo-PSObjectToHash -obj $DiscoveryMethods.ActiveDirectoryUserDiscovery.Settings
        #Grab the Schedule Settings
        $TempSchedule = $DiscoveryMethods.ActiveDirectoryUserDiscovery.Schedule.psobject.copy()
        #Convert the passed in Date/Time to the correct Format, and replace the Member Variable
        $TempSchedule | Add-Member -MemberType NoteProperty -Name 'Start' -Value (Get-Date -Date $TempSchedule.Start -Format "yyyy/MM/dd 00:00:00") -Force
        #Convert this to a hastable for splatting
        $ScheduleSplat = ConvertTo-PSObjectToHash -obj $TempSchedule
        #Create a new Schedule
        $Schedule = New-CMSchedule @ScheduleSplat
        #Set the Discovery Method with the new Schedule
        Set-CMDiscoveryMethod -ActiveDirectoryUserDiscovery -PollingSchedule $Schedule @SettingsSplat
    }

    if ($DiscoveryMethods.ActiveDirectoryGroupDiscovery) {
        #Grab the standard Settings
        $SettingsSplat = ConvertTo-PSObjectToHash -obj $DiscoveryMethods.ActiveDirectoryGroupDiscovery.Settings
        #Grab the Schedule Settings
        $TempSchedule = $DiscoveryMethods.ActiveDirectoryGroupDiscovery.Schedule.psobject.copy()
        #Convert the passed in Date/Time to the correct Format, and replace the Member Variable
        $TempSchedule | Add-Member -MemberType NoteProperty -Name 'Start' -Value (Get-Date -Date $TempSchedule.Start -Format "yyyy/MM/dd 00:00:00") -Force
        #Convert this to a hastable for splatting
        $ScheduleSplat = ConvertTo-PSObjectToHash -obj $TempSchedule
        #Create a new Schedule
        $Schedule = New-CMSchedule @ScheduleSplat
        #Get the Group Scope
        $CMGroupDiscoveryScopeSplat = ConvertTo-PSObjectToHash -obj $DiscoveryMethods.ActiveDirectoryGroupDiscovery.Scope
        $GroupScope = New-CMADGroupDiscoveryScope @CMGroupDiscoveryScopeSplat
        #Set the Discovery Method with the new Schedule
        Set-CMDiscoveryMethod -ActiveDirectoryGroupDiscovery -AddGroupDiscoveryScope $GroupScope -PollingSchedule $Schedule @SettingsSplat
    }

    if ($DiscoveryMethods.HeartbeatDiscovery) {
        #Grab the standard Settings
        $SettingsSplat = ConvertTo-PSObjectToHash -obj $DiscoveryMethods.HeartbeatDiscovery.Settings

        if ($DiscoveryMethods.HeartbeatDiscovery.Schedule) {
            #Grab the Schedule Settings
            $TempSchedule = $DiscoveryMethods.HeartbeatDiscovery.Schedule.psobject.copy()
            #Heartbeat doesnt support a starting value, so if supplied, remove it (will silently fail otherwise)
            if ($TempSchedule.Start) {
                $TempSchedule.psobject.properties.remove('Start')
            }
            #Convert this to a hastable for splatting
            $ScheduleSplat = ConvertTo-PSObjectToHash -obj $TempSchedule
            #Create a new Schedule
            $Schedule = New-CMSchedule @ScheduleSplat
            Set-CMDiscoveryMethod -Heartbeat -PollingSchedule $Schedule @SettingsSplat
        }
        else {
            #No schedule supplied, just set it
            Set-CMDiscoveryMethod -Heartbeat @SettingsSplat
        }
    }
} -ArgumentList $ConfigFile.SCCMInstallProps.SccmSiteCode, ($ConfigFile.SccmConfigProps.DiscoveryMethods)

Invoke-LabCommand -ActivityName 'Configuring Software Update Point (SUP)' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    param (
        [string]$SCCMSiteCode,
        [Object]$WSUSProps
    )

    function ConvertTo-PSObjectToHash {
        param (
            [Object]$Obj
        )
    
        $Hash = @{}
        foreach ( $property in $Obj.psobject.properties.name ) {
            $Hash[$property] = $Obj.$property
        }
        [HashTable]$Hash
    }

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if (-not (Get-CMSoftwareUpdatePoint -SiteSystemServerName $ProviderMachineName)) {
        Add-CMSoftwareUpdatePoint -SiteCode $SCCMSiteCode -SiteSystemServerName $ProviderMachineName
    }
    
    #At this stage, there is a disconnect between the SCCM Product List and the one WSUS has (was synced from Windows update during the initial WSUS config).
    # To stop unnecessary downloading of content, first disable all products and then force a sync. We will then use the products / product families in the
    # config file to reconfigure what products/categories and languages we want
    
    #Get all product items that are currently enabled
    $ActiveProducts = Get-CMSoftwareUpdateCategory -Fast | Where-Object {$_.IsSubscribed -eq $true -and $_.CategoryTypeName -eq 'Product'} | Select-Object -Property LocalizedCategoryInstanceName

    #Get a total list of products, this will be used to determine if the product categories have been incorporated after the update
    $BaseProductCount = $(Get-CMSoftwareUpdateCategory -Fast | Where-Object {$_.CategoryTypeName -eq 'Product'}).Count

    if ($ActiveProducts) {
        #Convert this to an array of strings
        $ProductsToDisable = $ActiveProducts | ForEach-Object {$_.LocalizedCategoryInstanceName}
        #Disable everything
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -RemoveProduct $ProductsToDisable
    }

    #Force a resync from within SCCM (this will update the product list to match WSUS)
    Sync-CMSoftwareUpdate -FullSync $false
    #Wait for the synchronisation to complete
    Do {
        #If currently synchronising, sleep for 1 minute before we check again
        If ($Syncronizing) {
            Start-Sleep -Seconds 60
        }

        $Syncronizing = $False
        ForEach ($softwareUpdatePointSyncStatus in Get-CMSoftwareUpdateSyncStatus) {
            If ($softwareUpdatePointSyncStatus.LastSyncState -eq 6704) {$Syncronizing = $True}
        }
    } Until(!$Syncronizing)

    #Wait until the update classifications have been incorporated into the main list.  This process can take an unknown amount of time
    # 30 minutes has been observed
    do {
        Start-Sleep 60
        $CurrentProductCount = $(Get-CMSoftwareUpdateCategory -Fast | Where-Object {$_.CategoryTypeName -eq 'Product'}).Count
        if ($CurrentProductCount -gt $BaseProductCount) {$ProductsAdded = $true} else {$ProductsAdded = $false}
    } until ($ProductsAdded)

    #Now reconfigure based on requirements in the Config File
    if ($WSUSProps.EnabledProductFamilies) {
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -AddProductFamily $WSUSProps.EnabledProductFamilies
    }

    if ($WSUSProps.EnabledProducts) {
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -AddProduct $WSUSProps.EnabledProducts
    }

    #Disabled products is typically used in concert with the EnabledProductFamilies above, if only one or two products in a given family arent required.
    # Rather than needing to list all products in a family, enable the whole family, then disable the ones that arent required.
    if ($WSUSProps.DisabledProducts) {
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -RemoveProduct $WSUSProps.DisabledProducts
    }
  
    if ($WSUSProps.EnabledClassifications) {
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -AddUpdateClassification $WSUSProps.EnabledClassifications
    }

    if ($WSUSProps.DisabledClassifications) {
        Set-CMSoftwareUpdatePointComponent -SiteCode $SCCMSiteCode -RemoveUpdateClassification $WSUSProps.DisabledClassifications
    }

    if ($WSUSProps.UpdateLanguages) {
        #If we have been provided a list of update languages, remove all selected update languages and replace it with the provided one
        #Languages should be the same as they appear in sccm, ie 'English' 'German' etc

        #Retrive the currently enabled update languages
        $EnabledTitleLanguages = ((Get-CMSoftwareUpdatePointComponent).Props | Where-Object {$_.PropertyName -eq 'SupportedTitleLanguages'}).Value2
        $EnabledUpdateLanguages = ((Get-CMSoftwareUpdatePointComponent).Props | Where-Object {$_.PropertyName -eq 'SupportedUpdateLanguages'}).Value2
        #SCCM Returns these enabled languages using their ISO code, but to remove them, they need to be converted into the relevant culture display name

        if ($EnabledTitleLanguages.Length -gt 0) {
            $CleanupTitleLanguages = @()
            foreach ($country in $EnabledTitleLanguages.Split(",")) {
                $culture = New-Object system.globalization.cultureinfo($country)
                $CleanupTitleLanguages += $culture.DisplayName
            }    

            Set-CMSoftwareUpdatePointComponent -RemoveLanguageSummaryDetail $CleanupTitleLanguages    
        }
        
        if ($EnabledUpdateLanguages.Length -gt 0) {
            $CleanupUpdateLanguages = @()
            foreach ($country in $EnabledUpdateLanguages.Split(",")) {
                $culture = New-Object system.globalization.cultureinfo($country)
                $CleanupUpdateLanguages += $culture.DisplayName
            }

            Set-CMSoftwareUpdatePointComponent -RemoveLanguageUpdateFile $CleanupUpdateLanguages
        }
                
        #Now replace that with the ones in the config file (we use the same list for both updates and summaries)
        Set-CMSoftwareUpdatePointComponent -AddLanguageUpdateFile $WSUSProps.UpdateLanguages -AddLanguageSummaryDetail $WSUSProps.UpdateLanguages
    }
    
    #BUG: Disabled currently due to no effect on the schedule configuration regardless of what schedule is put in
    # if ($WSUSProps.Schedule)
    # {
    #     #Update the Syunchronisation Schedule
    #     $TempSchedule = $WSUSProps.Schedule.psobject.copy()
    #     #Convert the passed in Date/Time to the correct Format, and replace the Member Variable
    #     $TempSchedule | Add-Member -MemberType NoteProperty -Name 'Start' -Value (Get-Date -Date $TempSchedule.Start -Format "yyyy/MM/dd 00:00:00") -Force
    #     #Convert this to a hastable for splatting
    #     $ScheduleSplat = ConvertTo-PSObjectToHash -obj $TempSchedule
    #     #Create a new Schedule
    #     $Schedule = New-CMSchedule @ScheduleSplat

    #     Set-CMSoftwareUpdatePointComponent -Schedule $Schedule 

    # }

    #Force a full update on the Software Updates (this will actually pull down content)
    #Dont wait for this to finish, could take several hours
    #Sync-CMSoftwareUpdate -FullSync $true

} -ArgumentList $ConfigFile.SCCMInstallProps.SccmSiteCode, $ConfigFile.SccmConfigProps.WSUSProps

Invoke-LabCommand -ActivityName 'Create Device Collections' -ComputerName "$($LabName)-CM1" -ScriptBlock {

    param (
        [string]$SCCMSiteCode,
        [Object]$DeviceCollections,
        [bool]$DeleteOnly = $false
    )
    function ConvertTo-PSObjectToHash {
        param (
            [Object]$Obj
        )
    
        $Hash = @{}
        foreach ( $property in $Obj.psobject.properties.name ) {
            $Hash[$property] = $Obj.$property
        }
        [HashTable]$Hash
    }

    If ((Get-Module ConfigurationManager) -eq $null) {
        Import-Module "C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1"
    }

    $SiteCode = $SCCMSiteCode
    $ProviderMachineName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName

    if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
    }

    $SiteCode = Get-PSDrive -PSProvider CMSITE                                                                        
    Set-Location ($SiteCode.Name + ":")

    foreach ($Collection in $DeviceCollections) { 

        if (Get-CMDeviceCollection -Name $Collection.BasicSettings.Name) {
            Remove-CMCollection -Name $Collection.BasicSettings.Name -Force
        }

        if (-not $DeleteOnly) {
            $NewCollectionHash = ConvertTo-PSObjectToHash -Obj $Collection.BasicSettings

            If ($Collection.Schedule) {
                $ScheduleSplat = ConvertTo-PSObjectToHash -obj $Collection.Schedule
                $Schedule = New-CMSchedule @ScheduleSplat
                New-CMDeviceCollection @NewCollectionHash -RefreshSchedule $Schedule
            }
            else {
                New-CMDeviceCollection @NewCollectionHash 
            }

            foreach ($Rule in $Collection.QueryMembershipRules) {
                $SingleRule = ConvertTo-PSObjectToHash -Obj $Rule
                Add-CMDeviceCollectionQueryMembershipRule -CollectionName $Collection.BasicSettings.Name @SingleRule
            }

            foreach ($Rule in $Collection.IncludeMembershipRules) {
                $SingleRule = ConvertTo-PSObjectToHash -Obj $Rule
                Add-CMDeviceCollectionIncludeMembershipRule -CollectionName $Collection.BasicSettings.Name @SingleRule
            }

            foreach ($Rule in $Collection.ExcludeMembershipRules) {
                $SingleRule = ConvertTo-PSObjectToHash -Obj $Rule
                Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $Collection.BasicSettings.Name @SingleRule
            }

            foreach ($Rule in $Collection.DirectMembershipRules) {
                $SingleRule = ConvertTo-PSObjectToHash -Obj $Rule
                $Device = Get-CMDevice @SingleRule
                Add-CMDeviceCollectionDirectMembershipRule -CollectionName $Collection.BasicSettings.Name -Resource $Device
            }
  
            foreach ($CollectionVariable in $Collection.Variables) {
                $SingleVariable = ConvertTo-PSObjectToHash -Obj $CollectionVariable
                New-CMDeviceCollectionVariable -CollectionName $Collection.BasicSettings.Name @SingleVariable
            }

            If ($Collection.Location) {
                $RootFolder = "$($SiteCode.Name):\DeviceCollection"
                $WorkingPath = $RootFolder
                foreach ($Item in $Collection.Location.Split("\")) {
                    if (-Not (Get-Item -Path $(Join-Path -Path $WorkingPath -ChildPath $item) -ErrorAction SilentlyContinue)) {
                        New-Item -Path $WorkingPath -Name $Item  
                    }
             
                    $WorkingPath = Join-Path -Path $WorkingPath -ChildPath $item
                }    
                Move-CMObject -FolderPath $WorkingPath -InputObject (Get-CMDeviceCollection -Name $Collection.BasicSettings.Name)
            }
        }   
    }
} -ArgumentList $ConfigFile.SCCMInstallProps.SccmSiteCode, $ConfigFile.SccmConfigProps.Collections.DeviceCollections


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


