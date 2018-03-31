<#
.SYNOPSIS
    Install a functional SCCM Primary Site using the Automated-Lab tookit with SCCM being installed using the "CustomRoles" approach
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
#>

param(

    [Parameter(Mandatory)]
    [string]$ComputerName,

    [string]$SCCMSiteCode = 'CM1',

    [string]$SCCMBinariesDirectory = "$labSources\SoftwarePackages\SCCM1702",

    [string]$SCCMPreReqsDirectory = "$labSources\SoftwarePackages\SCCMPreReqs"
)


function Install-SCCM {
    param  
    (
        [Parameter(Mandatory)]
        $SCCMServerName,

        [Parameter(Mandatory)]
        $SCCMBinariesDirectory,

        [Parameter(Mandatory)]
        $SCCMPreReqsDirectory,

        [Parameter(Mandatory)]
        $SCCMSiteCode = 'CM1'
    )

    $MDTDownloadLocation = 'https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi'

    #Do Some quick checks before we get going
    $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
    #Check for existance of ADK Installation Files
    if (!(Test-Path -Path (Join-Path -Path $downloadTargetFolder -ChildPath 'ADK'))) {
        Write-LogFunctionExitWithError -Message "ADK Installation files not located at '$(Join-Path -Path $downloadTargetFolder -ChildPath 'ADK')'"
        return
    }

    if (!(Test-Path -Path $SCCMBinariesDirectory)) {
        Write-LogFunctionExitWithError -Message "SCCM Installation files not located at '$(Join-Path -Path $downloadTargetFolder -ChildPath $SCCMBinariesDirectory)'"
        return
    }

    if (!(Test-Path -Path $SCCMPreReqsDirectory)) {
        Write-LogFunctionExitWithError -Message "SCCM PreRequisite files not located at '$(Join-Path -Path $downloadTargetFolder -ChildPath $SCCMPreReqsDirectory)'"
        return
    }

    #Bring all available disks online (this is to cater for the secondary drive)
    #For some reason, cant make the disk online and RW in the one command, need to perform two seperate actions
    Invoke-LabCommand -ActivityName 'Bring Disks Online' -ComputerName $SCCMServerName -ScriptBlock {
        $DataVolume = Get-Disk | Where-Object -Property OperationalStatus -eq Offline
        $DataVolume | Set-Disk -IsOffline $false
        $DataVolume | Set-Disk -IsReadOnly $false
    }
    
    #Copy the SCCM Binaries
    $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
    Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $SCCMBinariesDirectory) -DestinationFolderPath C:\Install -ComputerName $SCCMServerName -Recurse
    #Copy the SCCM Prereqs (must have been previously downloaded)
    Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $SCCMPreReqsDirectory) -DestinationFolderPath C:\Install -ComputerName $SCCMServerName -Recurse

    #Extend the AD Schema
    Invoke-LabCommand -ActivityName 'Extend AD Schema' -ComputerName $SCCMServerName -ScriptBlock {
        Start-Process -FilePath "C:\Install\SCCM1702\SMSSETUP\BIN\X64\extadsch.exe" -Wait
    }

    #Need to execute this command on the Domain Controller, since it has the AD Powershell cmdlets available
    $RootDC = Get-LabMachine | Where-Object {$_.Roles -like "RootDC"}
    #Create the Necessary OU and permissions for the SCCM container in AD

    Invoke-LabCommand -ActivityName 'Configure SCCM Systems Management Container' -ComputerName $RootDC -ScriptBlock {
        param  
            (
               [Parameter(Mandatory)]
               $SCCMServerName
           )

        Import-Module ActiveDirectory
        # Figure out our domain
        $DomainRoot = (Get-ADRootDSE).defaultNamingContext

        # Get or create the System Management container
        $ou = $null
        try
        {
            $ou = Get-ADObject "CN=System Management,CN=System,$DomainRoot"
        }
        catch
        {   
            Write-Verbose "System Management container does not currently exist."
        }

        #If the OU Doesnt already exist, create it
        if ($ou -eq $null)
        {
            $ou = New-ADObject -Type Container -name "System Management" -Path "CN=System,$DomainRoot" -Passthru
        }

        # Get the current ACL for the OU
        $acl = Get-ACL "ad:CN=System Management,CN=System,$DomainRoot"

        # Get the computer's SID (we need to get the computer object, which is in the form <ServerName>$)
        $SCCMComputer = Get-ADComputer "$SCCMServerName$"
        $SCCMServerSID = [System.Security.Principal.SecurityIdentifier] $SCCMComputer.SID

        $ActiveDirectoryRights = "GenericAll"
        $AccessControlType = "Allow"
        $Inherit = "SelfAndChildren"
        $nullGUID = [guid]'00000000-0000-0000-0000-000000000000'
 
        # Create a new access control entry to allow access to the OU
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SCCMServerSID, $ActiveDirectoryRights, $AccessControlType, $Inherit, $nullGUID
        
        # Add the ACE to the ACL, then set the ACL to save the changes
        $acl.AddAccessRule($ACE)
        Set-ACL -aclobject $acl "ad:CN=System Management,CN=System,$DomainRoot"

    } -ArgumentList $SCCMServerName

    Write-ScreenInfo -Message "Downloading MDT Installation Files from '$MDTDownloadLocation'"
    Get-LabInternetFile -Uri $MDTDownloadLocation -Path $downloadTargetFolder -ErrorAction Stop
   
    $MDTDownloadURL = New-Object System.Uri($MDTDownloadLocation)
    $MDTInstallFileName = $MDTDownloadURL.Segments[$MDTDownloadURL.Segments.Count-1]
   
    Write-ScreenInfo "Copying MDT Install Files to server '$SCCMServerName'..."
    Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $MDTInstallFileName) -DestinationFolderPath C:\Install -ComputerName $SCCMServerName
   
    Write-ScreenInfo "Copying ADK Install Files to server '$SCCMServerName'..."
    Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath 'ADK') -DestinationFolderPath C:\Install -ComputerName $SCCMServerName -Recurse
   
    Write-ScreenInfo "Installing ADK on server '$SCCMServerName'..."
    Invoke-LabCommand -ActivityName 'Install ADK' -ComputerName $SCCMServerName -ScriptBlock {
           Start-Process -FilePath "C:\Install\ADK\adksetup.exe" -ArgumentList "/norestart /q /ceip off /features OptionId.WindowsPreinstallationEnvironment OptionId.DeploymentTools OptionId.UserStateMigrationTool OptionId.ImagingAndConfigurationDesigner" -Wait
    }

    Install-LabWindowsFeature -ComputerName $SCCMServerName -FeatureName 'NET-Framework-Core'
   
    Invoke-LabCommand -ActivityName 'Install WDS Tools' -ComputerName $SCCMServerName -ScriptBlock {
           Add-WindowsFeature WDS -IncludeManagementTools | Out-Null
    }

    Write-ScreenInfo "Installing 'MDT' on server '$SCCMServerName'..."
    Install-LabSoftwarePackage -ComputerName $SCCMServerName -LocalPath "C:\Install\$MDTInstallFileName" -CommandLine '/qb'

    Invoke-LabCommand -ActivityName 'Configure WDS' -ComputerName $SCCMServerName -ScriptBlock {
        Start-Process -FilePath "C:\Windows\System32\WDSUTIL.EXE" -ArgumentList "/Initialize-Server /RemInst:C:\RemoteInstall" -Wait
        Start-Sleep -Seconds 10
        Start-Process -FilePath "C:\Windows\System32\WDSUTIL.EXE" -ArgumentList "/Set-Server /AnswerClients:All" -Wait
    }  

    #SCCM Needs a ton of additional features installed...
    Install-LabWindowsFeature -ComputerName $SCCMServerName -FeatureName 'FS-FileServer,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,Web-WMI,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-Http-Tracing,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Security,Web-Filtering,Web-Windows-Auth,Web-App-Dev,Web-Net-Ext,Web-Net-Ext45,Web-Asp-Net,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter'
    Install-LabWindowsFeature -ComputerName $SCCMServerName -FeatureName 'NET-HTTP-Activation,NET-Non-HTTP-Activ,NET-Framework-45-ASPNET,NET-WCF-HTTP-Activation45,BITS,RDC'

    #Before we start the SCCM Install, restart the computer
    Restart-LabVM -ComputerName $SCCMServerName -Wait

    #Build the Installation unattended .INI file
    $setupConfigFileContent = "
[Identification]
Action=InstallPrimarySite
      
[Options]
ProductID=EVAL
SiteCode=$SCCMSiteCode
SiteName=Primary Site 1
SMSInstallDir=D:\Program Files\Microsoft Configuration Manager
SDKServer=$((Get-LabMachineDefinition -ComputerName $SCCMServerName).FQDN)
RoleCommunicationProtocol=HTTPorHTTPS
ClientsUsePKICertificate=0
PrerequisiteComp=1
PrerequisitePath=C:\Install\SCCMPreReqs
MobileDeviceLanguage=0
ManagementPoint=$((Get-LabMachineDefinition -ComputerName $SCCMServerName).FQDN)
ManagementPointProtocol=HTTP
DistributionPoint=$((Get-LabMachineDefinition -ComputerName $SCCMServerName).FQDN)
DistributionPointProtocol=HTTP
DistributionPointInstallIIS=0
AdminConsole=1
JoinCEIP=0
       
[SQLConfigOptions]
SQLServerName=$((Get-LabMachineDefinition -ComputerName $SCCMServerName).FQDN)
DatabaseName=CM_$SCCMSiteCode
SQLSSBPort=4022
SQLDataFilePath=D:\CMSQL\SQLDATA\
SQLLogFilePath=D:\CMSQL\SQLLOGS\
       
[CloudConnectorOptions]
CloudConnector=0
CloudConnectorServer=$((Get-LabMachineDefinition -ComputerName $SCCMServerName).FQDN)
UseProxy=0
       
[SystemCenterOptions]
       
[HierarchyExpansionOption]"

       #Save the config file to disk, and copy it to the SCCM Server
       $SCCMInIFileLocation = Join-Path -Path $labSources -ChildPath PostInstallationActivities
       $setupConfigFileContent | Out-File -Encoding ascii -FilePath "$SCCMIniFileLocation\ConfigMgrUnattend.ini"  

       Copy-LabFileItem -Path "$SCCMIniFileLocation\ConfigMgrUnattend.ini"  -DestinationFolderPath C:\Install -ComputerName $SCCMServerName

       Invoke-LabCommand -ActivityName 'Install SCCM' -ComputerName $SCCMServerName -ScriptBlock {
            #SQL Server does not like creating databases without the directories already existing, so make sure to create them first
            New-Item -Path 'D:\CMSQL\SQLDATA' -ItemType Directory -Force | Out-Null
            New-Item -Path 'D:\CMSQL\SQLLOGS' -ItemType Directory -Force | Out-Null
            #Install SCCM. This step will take quite some time.
            Start-Process -FilePath "C:\Install\SCCM1702\SMSSETUP\BIN\X64\setup.exe" -ArgumentList "/Script ""C:\Install\ConfigMgrUnattend.ini"" /NoUserInput" -Wait
        }  

}


Import-Lab -Name $data.Name

Install-SCCM -SCCMServerName $ComputerName -SCCMBinariesDirectory $SCCMBinariesDirectory -SCCMPreReqsDirectory $SCCMPreReqsDirectory -SCCMSiteCode $SCCMSiteCode
