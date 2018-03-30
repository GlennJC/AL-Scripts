<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes

    https://docs.microsoft.com/en-us/microsoft-identity-manager/microsoft-identity-manager-deploy
    https://github.com/brianlala/AutoSPSourceBuilder
    https://github.com/brianlala/AutoSPInstaller

    Enterprise trial product key: NQGJR-63HC8-XCRQH-MYVCH-3J3QR
    Standard trial product key: RTNGH-MQRV6-M3BWQ-DB748-VH7DM

#>

Import-Module .\UserRights.ps1

$xmlSetupFile = @"
    <Configuration>
        <Package Id="sts">
            <Setting Id="LAUNCHEDFROMSETUPSTS" Value="Yes"/>
        </Package>
        <Package Id="spswfe">
            <Setting Id="SETUPCALLED" Value="1"/>
            <Setting Id="OFFICESERVERPREMIUM" Value="0" />
        </Package>
        <Logging Type="verbose" Path="%temp%" Template="SharePoint Server Setup(*).log"/>
        <Display Level="basic" CompletionNotice="No" AcceptEula="Yes"/>
        <INSTALLLOCATION Value=""/>
        <DATADIR Value=""/>
        <PIDKEY Value="RTNGH-MQRV6-M3BWQ-DB748-VH7DM"/>
        <Setting Id="SERVERROLE" Value="SINGLESERVER"/>
        <Setting Id="USINGUIINSTALLMODE" Value="1"/>
        <Setting Id="SETUPTYPE" Value="CLEAN_INSTALL"/>
        <Setting Id="SETUP_REBOOT" Value="Never"/>
        <Setting Id="AllowWindowsClientInstall" Value="True"/>
    </Configuration>
"@

$SPServiceAccounts = @{
    'svcSPFarm'='SharePoint Farm Account'
    'svcSPServices'='SharePoint Services Account'
    'svcSPPortalAppPool'='SharePoint Portal Account'
    'svcSPProfilesAppPool'='SharePoint MySite Account'
    'svcSPSearchService'='SharePoint Search Service Account'
    'svcSPCacheUser'='SharePoint Cache Super User Account'
    'svcSPCacheReader'='SharePoint Cache Reader Account'
}

$MIMServiceAccounts = @{
    'svcMIMMA'='MIM Management Agent Account'
    'svcMIMSync'='MIM Sync Account'
    'svcMIMService'='MIM Main Service Account'
    'svcMIMSSPR'=''
}

function Get-LabMachinePendingReboot {
    <#
    .SYNOPSIS
        Checks the remote Machine to see if a reboot is pending
    .INPUTS
        $ComputerName - Name of the Lab Machine to check
    .OUTPUTS
        a Custom PSObject containing which operation is causing the machine to want a reboot.
        To see if the machine needs a retsart (regardless of reason), example:

        $NeedsReboot = Get-LabMachinePendingReboot -ComputerName 'TEST-DC01'
        if ($NeedsReboot.RebootPending) {Restart-LabVM -ComputerName 'TEST-DC01' -Wait}

        1 Line Version:
        if ((Get-LabMachinePendingReboot -ComputerName 'TEST-DC01').RebootPending) {Restart-LabVM -ComputerName 'TEST-DC01' -Wait} else {Write-Host "No Reboot Required"}
    .NOTES
        Function is a modified version of the excellent script developed by Brian Wilhite, available at:
            https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542
    #>

    param (
        #Server to Check
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $RebootStatus = Invoke-LabCommand -ComputerName $ComputerName -ScriptBlock {

        param (
            #Server to Check
            [Parameter(Mandatory)]
            [string]$ComputerName
        )

        $CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false
        $CBSRebootPend = $null
						
        ## Querying WMI for build version
        $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ErrorAction Stop

        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\$ComputerName\root\default:StdRegProv"
						
        ## If Vista/2008 & Above query the CBS Reg Key
        If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
            $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
            $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
        }
        
        ## Query WUAU from the registry
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
                
        ## Query PendingFileRenameOperations from the registry
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
        $RegValuePFRO = $RegSubKeySM.sValue
        ## If PendingFileRenameOperations has a value set $PendFileRename variable to $true
        If ($RegValuePFRO) {
            $PendFileRename = $true
        }

        ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
        $Netlogon = $WMI_Reg.EnumKey($HKLM, "SYSTEM\CurrentControlSet\Services\Netlogon").sNames
        $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

        ## Query ComputerName and ActiveComputerName from the registry
        $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")            
        $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")

        #If the active and computername keys are different, machine has been renamed but not restarted
        If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
            $CompPendRen = $true
        }

        $CCMClientSDK = $null
        $CCMSplat = @{
            NameSpace    = 'ROOT\ccm\ClientSDK'
            Class        = 'CCM_ClientUtilities'
            Name         = 'DetermineIfRebootPending'
            ComputerName = $Computer
            ErrorAction  = 'Stop'
        }
        ## Try CCMClientSDK
        Try {
            $CCMClientSDK = Invoke-WmiMethod @CCMSplat
        }
        Catch [System.UnauthorizedAccessException] {
            $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
            If ($CcmStatus.Status -ne 'Running') {
                $CCMClientSDK = $null
            }
        }
        Catch {
            $CCMClientSDK = $null
        }

        If ($CCMClientSDK) {
            If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
                $SCCM = $true
            }
        }
            
        Else {
            $SCCM = $null
        }       

        $SelectSplat = @{
            Property = (
                'Computer',
                'CBServicing',
                'WindowsUpdate',
                'CCMClientSDK',
                'PendComputerRename',
                'PendFileRename',
                'PendFileRenVal',
                'RebootPending'
            )
        }
            
        New-Object -TypeName PSObject -Property @{
            Computer           = $WMI_OS.CSName
            CBServicing        = $CBSRebootPend
            WindowsUpdate      = $WUAURebootReq
            CCMClientSDK       = $SCCM
            PendComputerRename = $CompPendRen
            PendFileRename     = $PendFileRename
            PendFileRenVal     = $RegValuePFRO
            RebootPending      = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
        } | Select-Object @SelectSplat
        
    } -PassThru -NoDisplay -ArgumentList $ComputerName
   
    return $RebootStatus
}

function Install-Application {

    param (
       
        #hosts to install the application on
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        #URL for the application to be downloaded
        [Parameter(ParameterSetName = 'ByURL')]
        [string]$URL,

        #ISO Path for the installation ISO
        [Parameter(ParameterSetName = 'ByISO')]
        [string]$ISOPath,

        #Folder where existing installation files are located
        [Parameter(ParameterSetName = 'ByPath')]
        [string]$DirectoryPath,

        #Path relative to source media where installation executable is located. If a URL was provided, it is assumed the InstallExecutable is the last segment in the URL name
        [parameter(Mandatory, ParameterSetName = 'ByISO')]
        [parameter(Mandatory, ParameterSetName = 'ByPath')]
        [ValidateNotNullOrEmpty()]
        [string]$InstallExecutable,

        #Whether the files should be copied to a subfolder of the C:\Install directory
        [parameter(ParameterSetName = 'ByURL')]
        [string]$SubFolder,

        #Required arguments for the installation
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$InstallArguments,

        #Whether to execute the file in place or not (Assumed that the Directory path is fully qualified)
        #typically used when we want to install an App from somewhere on the file system, but dont want to copy the files into the C:\Install directory
        [parameter(ParameterSetName = 'ByPath')]
        [switch]$NoCopy,

        # Restart the machine after application installation? Valid values are:
        # Always = Always Restart, even if not needed
        # Needed = Only restart if the Get-LabMachinePendingRestart is true
        # Never = Never Restart
        # If no value provided, machine will only restart if required.
        [ValidateSet('Always', 'Needed', 'Never')] 
        [string]$Reboot = 'Needed'
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ByURL' {
            #We were passed a URL of the application to install, download if necessary
            $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
            $DestinationFolderPath = 'C:\Install'
            if ($SubFolder) {
                $downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath $SubFolder
                if (!(Test-Path -Path $downloadTargetFolder)) {
                    New-Item -Path $downloadTargetFolder -ItemType 'Directory' -Force
                }

                $DestinationFolderPath = Join-Path -Path 'C:\Install' -ChildPath $SubFolder
            }

            $internalUri = New-Object System.Uri($URL)
            Get-LabInternetFile -Uri $internalUri -Path $downloadTargetFolder -ErrorAction Stop 
            $DownloadedFileName = $internalUri.Segments[$internalUri.Segments.Count - 1]
            Write-ScreenInfo 'Copying source files to Target Servers' -TaskStart
            Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $DownloadedFileName) -DestinationFolderPath $DestinationFolderPath -ComputerName $ComputerName
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath (Join-Path -Path $DestinationFolderPath -ChildPath $DownloadedFileName) -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
        }
        'ByPath' {
            #See if the NoCopy flag was passed
            if ($NoCopy) {
                #Execute the file in place.
                $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "$DirectoryPath\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
                $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
            }
            else {
                #Copy in the files to the C:\Install directory and execute from there. $InstallExecutable will be relative to the C:\Install Directory
                Write-ScreenInfo 'Copying source directories to Target Servers' -TaskStart
                Copy-LabFileItem -Path $DirectoryPath -DestinationFolderPath 'C:\Install' -ComputerName $ComputerName -Recurse 
                Write-ScreenInfo 'Finished Copying Files' -TaskEnd
                $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "C:\Install\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
                $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
            }
            
        }
        'ByISO' {
            Write-ScreenInfo 'Mounting ISO on target servers' -TaskStart
            $disk = Mount-LabIsoImage -ComputerName $ComputerName -IsoPath $ISOPath -PassThru -SupressOutput
            Write-ScreenInfo 'Finished' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "$($disk.DriveLetter)\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
            Dismount-LabIsoImage -ComputerName $ComputerName -SupressOutput
    
        }
    }

    foreach ($SingleComputer in $ComputerName) {

        switch ($Reboot) {
            'Always' {
                Write-ScreenInfo -Message "Server $SingleComputer is being restarted, Always Flag set"
                Restart-LabVM -ComputerName $SingleComputer -Wait
            }
            'Needed' {
                if ((Get-LabMachinePendingReboot -ComputerName $SingleComputer).RebootPending) {
                    Write-ScreenInfo -Message "Server $SingleComputer requires a restart before continuing. Needed Flag set, restarting"
                    Restart-LabVM -ComputerName $SingleComputer -Wait
                }
            }
            'Never' {
                if ((Get-LabMachinePendingReboot -ComputerName $SingleComputer).RebootPending) {
                    Write-ScreenInfo -Message "Server $SingleComputer requires a restart before continuing. Never Flag Set, NOT restarting"
                }
            }
        }
    }
    
}

function Initialize-SharePoint2016Accounts {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    #Create the necessary AD Accounts by perfrming on the RootDC role server
    Invoke-LabCommand -ActivityName 'Create AD Accounts and Groups' -ComputerName (Get-LabMachine -Role 'RootDC') -ScriptBlock {

        param (
            [Parameter(Mandatory)]
            [hashtable]$SPServiceAccounts
        )

        $password = "Password1"
        $securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
        import-module ActiveDirectory
    
        #Create Service accounts
        $Path = "OU=ServiceAccounts,$((Get-ADDomain).DistinguishedName)"
        if(![adsi]::Exists("LDAP://$Path"))
        {
            New-ADOrganizationalUnit -Name 'ServiceAccounts' -PassThru -ProtectedFromAccidentalDeletion:$false
        }

        $SPServiceAccounts.GetEnumerator() | Foreach-Object {
            New-ADUser -Name $($_.Key) -SAMAccountName $($_.Key) -AccountPassword $securePassword -Description $($_.Value) -Path $Path -Enabled $true -PasswordNeverExpires $true 
        }
    
    } -ArgumentList $SPServiceAccounts

    #Temporarily add the Farm Service account into local admins on the SharePoint Server (will be removed after the build)
    Invoke-LabCommand -ActivityName 'Create AD Accounts and Groups' -ComputerName $ComputerName -ScriptBlock {
        $Computer = Get-WmiObject -Class Win32_ComputerSystem -namespace "root\CIMV2"
        Add-LocalGroupMember -Group 'Administrators' -Member "$($Computer.Domain)\svcSPFarm" -ErrorAction SilentlyContinue
    }

}

function Install-SharePoint2016Prereqs {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $PreReqFiles2016 = @{
        "Microsoft .NET Framework 4.6"="https://download.microsoft.com/download/C/3/A/C3A5200B-D33C-47E9-9D70-2F7C65DAAD94/NDP46-KB3045557-x86-x64-AllOS-ENU.exe"
          "Microsoft SQL Server 2012 Native Client"="http://download.microsoft.com/download/4/B/1/4B1E9B0E-A4F3-4715-B417-31C82302A70A/ENU/x64/sqlncli.msi"
          "Microsoft ODBC Driver 11 for SQL Server"="https://download.microsoft.com/download/5/7/2/57249A3A-19D6-4901-ACCE-80924ABEB267/ENU/x64/msodbcsql.msi"
          "Microsoft Sync Framework Runtime v1.0 SP1 (x64)"="http://download.microsoft.com/download/E/0/0/E0060D8F-2354-4871-9596-DC78538799CC/Synchronization.msi"
          "Microsoft Identity Extensions"="http://download.microsoft.com/download/0/1/D/01D06854-CA0C-46F1-ADBA-EBF86010DCC6/rtm/MicrosoftIdentityExtensions-64.msi" 
          "Microsoft Information Protection and Control Client 2.1"="http://download.microsoft.com/download/3/C/F/3CF781F5-7D29-4035-9265-C34FF2369FA2/setup_msipc_x64.exe" 
          "Microsoft WCF Data Services 5.6"="http://download.microsoft.com/download/1/C/A/1CAA41C7-88B9-42D6-9E11-3C655656DAB1/WcfDataServices.exe" 
          "Windows Server AppFabric"="http://download.microsoft.com/download/A/6/7/A678AB47-496B-4907-B3D4-0A2D280A13C0/WindowsServerAppFabricSetup_x64.exe" 
          "CU Package 1 for Microsoft AppFabric 1.1 for Windows Server (KB2671763)"="http://download.microsoft.com/download/7/B/5/7B51D8D1-20FD-4BF0-87C7-4714F5A1C313/AppFabric1.1-RTM-KB2671763-x64-ENU.exe" 
          "CU Package 7 for Microsoft AppFabric 1.1 for Windows Server (KB3092423)"="https://download.microsoft.com/download/F/1/0/F1093AF6-E797-4CA8-A9F6-FC50024B385C/AppFabric-KB3092423-x64-ENU.exe" 
          "Update for Microsoft .NET Framework to disable RC4 in Transport Layer Security (KB2898850)"="http://download.microsoft.com/download/C/6/9/C690CC33-18F7-405D-B18A-0A8E199E531C/Windows8.1-KB2898850-x64.msu" 
          "Visual C++ Redistributable Package for Visual Studio 2012"="http://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" 
          "Visual C++ Redistributable Package for Visual Studio 2015"="http://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe" 
    }
    
    #This will become a folder under the LabSources\SoftwarePadckagesFolder
    $SPPreReqsFolder = 'SharePointPreReqs'
    $DestinationFolderPath = Join-Path -Path 'C:\Install' -ChildPath $SPPreReqsFolder
    $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
    $downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath $SPPreReqsFolder

    #Create the Directory in SoftwarePackages if it doesnt exist
    if (!(Test-Path -Path $downloadTargetFolder)) {
        New-Item -Path $downloadTargetFolder -ItemType 'Directory' -Force | Out-Null
    }

    #Download all the necessary Pre-Req Files (if required)
    $PreReqFiles2016.GetEnumerator() | Foreach-Object {
        $internalUri = New-Object System.Uri($_.Value)
        Get-LabInternetFile -Uri $internalUri -Path $downloadTargetFolder -ErrorAction Stop 
        $DownloadedFileName = $internalUri.Segments[$internalUri.Segments.Count - 1]
        Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $DownloadedFileName) -DestinationFolderPath $DestinationFolderPath -ComputerName $ComputerName
    }

    #Perform the Feature installation under the control of AutomatedLab, since it handles the sxs issue correctly
    #The pre-requisites installer will simply skip over this activity since it has already been done
    Install-LabWindowsFeature -ComputerName $ComputerName -FeatureName 'Net-FrameWork-Features,RSAT-AD-PowerShell,Server-Media-Foundation,NET-HTTP-Activation,NET-Non-HTTP-Activ,NET-WCF-Pipe-Activation45,NET-WCF-HTTP-Activation45,Web-Server,Web-WebServer,Web-Common-Http,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-App-Dev,Web-Asp-Net,Web-Asp-Net45,Web-Net-Ext,Web-Net-Ext45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-Http-Tracing,Web-Security,Web-Basic-Auth,Web-Windows-Auth,Web-Filtering,Web-Digest-Auth,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,WAS,WAS-Process-Model,WAS-NET-Environment,WAS-Config-APIs,Web-Lgcy-Scripting,Windows-Identity-Foundation,Xps-Viewer'
    Restart-LabVM -ComputerName $ComputerName -Wait

    #Build the ArgumentsList (easier to debug this way)
    $PreReqArgumentList = "/unattended "
    $PreReqArgumentList += "/SQLNCli:""$DestinationFolderPath\sqlncli.msi"" "
    $PreReqArgumentList += "/DotNetFx:""$DestinationFolderPath\NDP46-KB3045557-x86-x64-AllOS-ENU.exe"" "
    $PreReqArgumentList += "/ODBC:""$DestinationFolderPath\msodbcsql.msi"" "
    $PreReqArgumentList += "/IDFX11:""$DestinationFolderPath\MicrosoftIdentityExtensions-64.msi"" "
    $PreReqArgumentList += "/Sync:""$DestinationFolderPath\Synchronization.msi"" "
    $PreReqArgumentList += "/AppFabric:""$DestinationFolderPath\WindowsServerAppFabricSetup_x64.exe"" "
    $PreReqArgumentList += "/KB3092423:""$DestinationFolderPath\AppFabric-KB3092423-x64-ENU.exe"" "
    $PreReqArgumentList += "/MSIPCClient:""$DestinationFolderPath\setup_msipc_x64.exe"" "
    $PreReqArgumentList += "/WCFDataServices56:""$DestinationFolderPath\WcfDataServices.exe"" "
    $PreReqArgumentList += "/MSVCRT11:""$DestinationFolderPath\vcredist_x64.exe"" "
    $PreReqArgumentList += "/MSVCRT14:""$DestinationFolderPath\vc_redist.x64.exe"" "

    #Mount the SharePoint ISO to the target machine
    $disk = Mount-LabIsoImage -ComputerName $ComputerName -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'SharePoint2016'}).Path -PassThru -SupressOutput
    #Do the pre-reqs install from the Sharepoint CD. Always reboot flag has been passed, as the WCFDataServices needs to restart for component registation to occur
    Install-Application -ComputerName $ComputerName -NoCopy -DirectoryPath "$($disk.DriveLetter)" -InstallExecutable "prerequisiteinstaller.exe" -InstallArguments $PreReqArgumentList -Reboot Always
}

Function Initialize-SharePoint2016Farm {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    Invoke-LabCommand -ActivityName 'Install Configuration Database' -ComputerName $ComputerName -ScriptBlock {

        param (
        [Parameter(Mandatory)]
        [string]$ComputerName
        )

        Add-PSSnapin Microsoft.SharePoint.PowerShell
        $secPassword = ConvertTo-SecureString "Password1" -AsPlaintext -Force
        $NETBIOSDomainName = (Get-ADDomain -Identity (Get-WmiObject Win32_ComputerSystem).Domain).NetBIOSName
        $farmCredential = New-Object System.Management.Automation.PsCredential "$NETBIOSDomainName\svcSPFarm",$secPassword
        New-SPConfigurationDatabase -DatabaseName "SharePoint_Config" -DatabaseServer $ComputerName -AdministrationContentDatabaseName "Content_CentralAdmin" -Passphrase $secPassword -FarmCredentials $farmCredential -LocalServerRole SingleServerFarm
    } -ArgumentList $ComputerName

    Invoke-LabCommand -ActivityName 'Configure SharePoint' -ComputerName $ComputerName -ScriptBlock {

        param (
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [hashtable]$SPServiceAccounts
        )

        $CentralAdminPort = 2016
        Add-PSSnapin Microsoft.SharePoint.PowerShell
        Initialize-SPResourceSecurity 
        Install-SPService 
        Install-SPFeature -AllExistingFeatures 
        New-SPCentralAdministration -Port $CentralAdminPort -WindowsAuthProvider 'NTLM' 
        Install-SPHelpCollection -All 
        Install-SPApplicationContent 

        $secPassword = ConvertTo-SecureString "Password1" -AsPlaintext -Force
        #We need to get the netbios name for the domain, as the New-SPManagedAccount will take a FQDN Domain Name, but register it
        # with the netbios name. Issue arrises if we then search using the FQDN Domain name, it returns a "Not Found", but will fail
        # on account registration since the managed account exists.
        #TL;DR - Have to use NETBIOS Domain Name to make this work.
        $NETBIOSDomainName = (Get-ADDomain -Identity (Get-WmiObject Win32_ComputerSystem).Domain).NetBIOSName

        #Loop through each of the service acccounts, see if they are already registered as a Managed Account. If not, add it.
        $SPServiceAccounts.GetEnumerator() | Foreach-Object {
            if (!(Get-SPManagedAccount -Identity "$NETBIOSDomainName\$($_.Key)" -ErrorAction SilentlyContinue)) {
                $UserCredential = New-Object System.Management.Automation.PsCredential "$NETBIOSDomainName\$($_.Key)",$secPassword
                New-SPManagedAccount -Credential $UserCredential
            }
        }
    } -ArgumentList $ComputerName, $SPServiceAccounts
}

function Install-Sharepoint2016 {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    #Create the Necessary AD Accounts
    Initialize-SharePoint2016Accounts -ComputerName $ComputerName
    #Install the Pre-Requisites, downloading if necessary
    Install-SharePoint2016Prereqs -ComputerName $ComputerName

    #Do the Main SharePoint Installation
    $XMLFileLocation = Join-Path -Path $labSources -ChildPath PostInstallationActivities
    $xmlSetupFile | Out-File -Encoding ascii -FilePath "$XMLFileLocation\SP2016Unattend.xml"  
    Copy-LabFileItem -Path "$XMLFileLocation\SP2016Unattend.xml"  -DestinationFolderPath C:\Install -ComputerName $MIMHost
    Install-Application -ComputerName $ComputerName -NoCopy -DirectoryPath "$($disk.DriveLetter)" -InstallExecutable "setup.exe" -InstallArguments '/config "C:\Install\SP2016Unattend.XML"' -Reboot Never

    Invoke-LabCommand -ActivityName 'Stop Configuration Wizard' -ComputerName $ComputerName -ScriptBlock {
        Write-Host "Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
        While ((Get-Process | Where-Object {$_.ProcessName -like "psconfigui*"}) -eq $null) {
            Write-Host "." -NoNewline
            Start-Sleep 1
        }
        Write-Host "Done."
        Write-Host "Exiting Products and Technologies Wizard"
        Stop-Process -Name psconfigui
    }

    Initialize-SharePoint2016Farm -ComputerName $ComputerName
}

function Initialize-MIM2016Accounts {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    #Create the necessary AD Accounts by perfrming on the RootDC role server
    Invoke-LabCommand -ActivityName 'Create AD Accounts and Groups' -ComputerName (Get-LabMachine -Role 'RootDC') -ScriptBlock {

        param (
            [Parameter(Mandatory)]
            [string]$MIMServerName,

            [Parameter(Mandatory)]
            [hashtable]$ServiceAccounts
        )

        $password = "Password1"
        $securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
        import-module ActiveDirectory
    
        #Create Service accounts
        $Path = "OU=ServiceAccounts,$((Get-ADDomain).DistinguishedName)"
        if(![adsi]::Exists("LDAP://$Path"))
        {
            New-ADOrganizationalUnit -Name 'ServiceAccounts' -PassThru -ProtectedFromAccidentalDeletion:$false
        }

        $GroupPath = "OU=AdminGroups,$((Get-ADDomain).DistinguishedName)"
        if(![adsi]::Exists("LDAP://$GroupPath"))
        {
            New-ADOrganizationalUnit -Name 'AdminGroups' -PassThru -ProtectedFromAccidentalDeletion:$false
        }


        $ServiceAccounts.GetEnumerator() | Foreach-Object {
            New-ADUser -Name $($_.Key) -SAMAccountName $($_.Key) -AccountPassword $securePassword -Description $($_.Value) -Path $Path -Enabled $true -PasswordNeverExpires $true 
        }

        New-ADGroup –name MIMSyncAdmins –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncAdmins -Path $GroupPath
        New-ADGroup –name MIMSyncOperators –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncOperators -Path $GroupPath
        New-ADGroup –name MIMSyncJoiners –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncJoiners -Path $GroupPath
        New-ADGroup –name MIMSyncBrowse –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncBrowse -Path $GroupPath
        New-ADGroup –name MIMSyncPasswordReset –GroupCategory Security –GroupScope Global –SamAccountName MIMSyncPasswordReset -Path $GroupPath
        Add-ADGroupMember -identity MIMSyncAdmins -Members Administrator
        Add-ADGroupmember -identity MIMSyncAdmins -Members svcMIMService

        #Create SPN's
        $MIMComputerAccount = Get-AdComputer -Identity $MIMServerName
        setspn -S "http/$($MIMComputerAccount.DNSHostName)" "$($(Get-AdDomain).NetBIOSName)\svcSPFarm"
        setspn -S "http/$($MIMComputerAccount.Name)" "$($(Get-AdDomain).NetBIOSName)\svcSPFarm"
        setspn -S "FIMService/$($MIMComputerAccount.DNSHostName)" "$($(Get-AdDomain).NetBIOSName)\svcMIMService"
    
    } -ArgumentList $ComputerName, $MIMServiceAccounts

}
function Install-MIM2016 {

    param (
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    $MIMPortalPrefix = "idm"


    Invoke-LabCommand -ActivityName 'Create MIM Portal' -ComputerName $ComputerName -ScriptBlock {

        param (
            [Parameter(Mandatory)]
            [string]$MIMPortalPrefix
        )
        
        Add-PSSnapin Microsoft.SharePoint.PowerShell
        $NETBIOSDomainName = (Get-ADDomain -Identity (Get-WmiObject Win32_ComputerSystem).Domain).NetBIOSName
        $dbManagedAccount = Get-SPManagedAccount -Identity "$NetBIOSDomainName\svcSPPortalAppPool"

        $MIMPortalURL = "http://$MIMPortalPrefix.$((Get-WmiObject Win32_ComputerSystem).Domain)"
        $MIMPortalPort = 82
        $MIMPortalName = "MIM Portal"
        New-SpWebApplication -Name $MIMPortalName -ApplicationPool "MIMAppPool" -ApplicationPoolAccount $dbManagedAccount -AuthenticationMethod "Kerberos" -Port $MIMPortalPort -URL $MIMPortalURL

        $SPTemplate = Get-SPWebTemplate -compatibilityLevel 15 -Identity "STS#1"
        $MIMPortalWebApp = Get-SPWebApplication $($MIMPortalURL + ":" + $MIMPortalPort)
        New-SPSite -Url $MIMPortalWebApp.Url -Template $SpTemplate -OwnerAlias "$NETBIOSDomainName\Administrator" -CompatibilityLevel 15 -Name $MIMPortalName

        $contentService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService;
        $contentService.ViewStateOnServer = $false;
        $contentService.Update();
        Get-SPTimerJob hourly-all-sptimerservice-health-analysis-job | disable-SPTimerJob
    } -ArgumentList $MIMPortalPrefix

    $MIMIPv4Address = (Get-LabMachine -ComputerName $ComputerName).IpAddress.IpAddress.AddressAsString

    Invoke-LabCommand -ActivityName 'Add Portal DNS Entry' -ComputerName (Get-LabMachine -Role 'RootDC') {

        param (
            [Parameter(Mandatory)]
            [string]$MIMIPv4Address,

            [Parameter(Mandatory)]
            [string]$MIMPortalPrefix

        )

        if (!(Get-DnsServerResourceRecord -Name $MIMPortalPrefix -ZoneName $((Get-WmiObject Win32_ComputerSystem).Domain) -ErrorAction SilentlyContinue)) {
            Add-DnsServerResourceRecordA -Name $MIMPortalPrefix -ZoneName $((Get-WmiObject Win32_ComputerSystem).Domain) -AllowUpdateAny -IPv4Address $MIMIPv4Address
        }

    } -ArgumentList $MIMIPv4Address, $MIMPortalPrefix

    $disk = Mount-LabIsoImage -ComputerName $ComputerName -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'MIM2016'}).Path -PassThru -SupressOutput
    
}

$labName = 'MIMLab'
$labSources = Get-LabSourcesLocation

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network'         = $labName
    'Add-LabMachineDefinition:ToolsPath'       = "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName'      = 'mimlab.local'
    'Add-LabMachineDefinition:DnsServer1'      = '192.168.50.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.50.0/24
Add-LabIsoImageDefinition -Name SQLServer2014 -Path $labSources\ISOs\en_sql_server_2014_standard_edition_x64_dvd_3932034.iso
Add-LabIsoImageDefinition -Name SharePoint2016 -Path $labSources\ISOs\OfficeServer.iso
Add-LabIsoImageDefinition -Name MIM2016 -Path $labSources\ISOs\MIM2016SP1EVAL.iso

Add-LabMachineDefinition -Name MIM-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.50.10'

$SQLInstallProperties = @{
    SQLSvcAccount  = 'MIMLAB\svcSQLServer'
    SQLSvcPassword = 'Pass@word1'
    Features       = 'SQL,SSMS'
}

#Add the SQL ROle definition. SCCM requires a specific Collation setting, so pass that in
$roles = (Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties $SQLInstallProperties)
Add-LabMachineDefinition -Name MIM-MIM1 -Memory 8GB -Processors 4 -Roles $roles -IpAddress '192.168.50.20' 

#Do the installation
Install-Lab 

Checkpoint-LabVM -All -SnapshotName 'After Build'

Install-Sharepoint2016 -ComputerName 'MIM-MIM1'

Checkpoint-LabVM -All -SnapshotName 'After SharePoint Install'

#Install-MIM2016 -ComputerName 'MIM-MIM1'


