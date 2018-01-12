
<#
    Author: Glenn Corbett @glennjc (GitHub)
    Version: 1.1, 19/12/2017
    Revision History (yyyy-mm-dd)
    1.0 - 2017-12-12 Initial Release
    1.1 - 2017-12-19 Optimised code for mounting ISO files and retrieving mounted driver letter, fix provied by @randree
#>

function Install-MDTDHCP ($ComputerName, $DHCPScopeName, $DHCPScopeStart, $DHCPScopeEnd, $DHCPScopeMask, $DHCPScopeDescription) {
    <#
    .SYNOPSIS
        Install and Configure DHCP + WDS DHCP Options
    .DESCRIPTION
        This function performs the following tasks

        1. Installs DHCP Service
        2. Adds the defined DHCP Server Scope
        3. Configured WDS to not listen on DHCP ports, and configure Option 60 in DHCP
        4. Binds the default Ethernet IPv4 interface to allow DHCP to listen.

    .EXAMPLE
        Install-MDTDHCP -ComputerName 'MDTServer' -DHCPScopeName 'Default Scope for DHCP' -DHCPscopeDescription 'Default Scope' -DHCPScopeStart 192.168.50.100 -DHCPScopeEnd 192.168.50.110 -DHCPScopeMask 255.255.255.0
        Installs DHCP and the 'MDTServer' configuring a DHCP scope of 192.168.50.100-110
    .INPUTS
        [string]$DHCPScopeName - Name of the scope as it will appear in DHCP
        [string]$DHCPScopeDescription - Description of the scope as it will appear in DHCP
        [string]$DHCPScopeStart - Starting address for the scope
        [string]$DHCPScopeEnd  - Ending address for the scope
        [string]$DHCPScopeMask - Subnet mask for the scope
    .OUTPUTS
        Nil
    .NOTES
        Feature Enhancement: Function assumes DHCP and WDS are on the same server, does not take into account split roles.
        Feature Enhancement: Deal with the requirement for DHCP servers to be authorised in AD environments
        Feature Enhancement: Validate DHCP Scope settings are valid for the AL networking configuration
        Feature Enhancement: Allow additonal DHCP scope options (such as DNS, Gateway etc)
        Feature Enhancement: Allow DHCP to bind to all / some available interfaces, currently assumes 'Ethernet'
    #>

    Invoke-LabCommand -ActivityName 'Installing and Configuring DHCP' -ComputerName $ComputerName -ScriptBlock {
        param  
        (
            [string]$DHCPScopeName = 'Default Scope',
            [string]$DHCPScopeDescription = 'Default Scope for WDS',

            [Parameter(Mandatory)]
            [string]$DHCPScopeStart,

            [Parameter(Mandatory)]
            [string]$DHCPScopeEnd,

            [Parameter(Mandatory)]
            [string]$DHCPScopeMask
        )

        Install-WindowsFeature DHCP -IncludeManagementTools -IncludeAllSubFeature | Out-Null
        Start-Sleep -Seconds 10
        Import-Module DHCPServer
        Add-DhcpServerv4Scope -Name $DHCPScopeName -StartRange $DHCPScopeStart -EndRange $DHCPScopeEnd -SubnetMask $DHCPScopeMask -Description $DHCPScopeDescription
        Start-Sleep -Seconds 10
        Start-Process -FilePath "C:\Windows\System32\WDSUtil.exe" -ArgumentList "/Set-Server /UseDHcpPorts:No" -Wait
        Start-Process -FilePath "C:\Windows\System32\WDSUtil.exe" -ArgumentList "/Set-Server /DHCPOption60:Yes" -Wait
        Start-Sleep -Seconds 10
        #Bind the Ethernet Adapter so that it can process DHCP Requests
        Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias "Ethernet" | Out-Null
               
    } -ArgumentList $DHCPScopeName, $DHCPScopeDescription, $DHCPScopeStart, $DHCPScopeEnd, $DHCPScopeMask -PassThru
}

function Import-MDTOS {
    <#
    .SYNOPSIS
        Imports an Operating System ISO into MDT as an available Operating Sytem
    .DESCRIPTION
        The function performs the following tasks

        1. Dismounts any existing ISO files in the image that may be left over from the lab installation (causes mutiple driver letters to be returned)
        2. Mounts the provided ISOPath (can use an existing AL OperatingSystem defintion, see example in notes)
        3. Checks with the VM to see what drive letter it was mounted as
        4. Imports the OS using MDT-ImportOperatingSystem
        5. Dismounts the ISO

    .EXAMPLE
        Import-MDTOS -ComputerName 'MDTServer' -ISOPath 'C:\LabSources\ISOs\SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-2_MLF_X21-22843.ISO' -OSFriendlyName 'Windows Server 2016' -DeploymentFolder 'C:\DeploymentFolder'
        Imports the Windows Server 2016 Server ISO to the 'MDTServer' with the friendly name 'Windows Server 2016' into the 'C:\DeploymentFolder'
    .INPUTS
        [string]$ComputerName - Name of the MDTServer prepared using AL
        [AutomatedLab.OperatingSystem]$OperatingSystem (OperatingSystem Parameter Set) - AL Object containing the OS to be imported, obtained from Get-LabAvailableOperatingSystems
        [string]$ALOSFriendlyName (OperatingSystem Parameter Set) - Name as the OS will appear on-disk and in deployment workbench structure. If not supplied, will use the one within the AL Object Definition (OperatingSystemName)
        [string]$ISOPath (ISO Parameter Set)- Fully qualified Path containing the Operating System ISO file
        [string]$ISOFriendlyName (ISO Parameter Set) - Name as the OS will appear on-disk and in deployment workbench structure
        [string]$DeploymentFolder - Fully Qualified path for the MDT Deployment Folder
    .OUTPUTS
        Nil
    .NOTES
        1. Function Supports either an ISO Path, or AutomatedLab.OperatingSystem Object using Parameter Sets
        2. OS' are imported whereby the on-disk file structure under the MDT Deployment Share\Operating Systems is the same as it appears in deployment workbench.
        3. Where an install.wim file contains mutiple operating systems (for example server .ISO's), ALL available images will be created in MDT. This means for a server import, you may end up with 4 or more available Operating Systems
        4. Feature Ehancement: Currently routine requires a single [AutomatedLab.OperatingSystem] object to be passed, enhane routine to either import multiple OS's or only import the first one
    #>

    param(
        #Name of the computer to run this on
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Alias('OS')]
        [Parameter(ParameterSetName="OperatingSystem")]
        [AutomatedLab.OperatingSystem]$OperatingSystem,

        #ISO Path of the Operating System ISO to be loaded into MDT
        [Parameter(ParameterSetName="ISO")]
        [string]$ISOPath,          

        #Friendly Name for the OS Folder as it will appear in MDT Deployment Workbench Heirachy
        [Parameter(Mandatory, ParameterSetName = "ISO")]
        [string]$ISOFriendlyName,

        #Friendly Name for the OS Folder as it will appear in MDT Deployment Workbench Heirachy
        [Parameter(ParameterSetName = "OperatingSystem")]
        [string]$ALOSFriendlyName,

        #Directory Path where the MDT Deployment Folder is located
        [Parameter(Mandatory)]
        [string]$DeploymentFolder
    )

    #Ensure that no other ISO images are mounted
    Dismount-LabIsoImage -ComputerName $ComputerName

    #If we were passed an ISO path, use that
    if ($ISOPath) {
        #Mount the ISO into the VM
        #Fix provied by @randree to use passed back mount object which contains the drive letter
        $MountedOSImage = Mount-LabIsoImage -IsoPath $ISOPath -ComputerName $ComputerName -PassThru
    
    } else {
        #Mount the ISO Referenced by the ISOPath property of the AutomatedLab.OperatingSystem Type
        #Fix provied by @randree to use passed back mount object which contains the drive letter
        $MountedOSImage = Mount-LabIsoImage -IsoPath $OperatingSystem.ISOPath -ComputerName $ComputerName -PassThru
    }

    #Work out what the friendly name for the OS should be
    if ($ISOFriendlyName) {
        #We were passed a friendly name when an ISO was specified, use that
        $OSFriendlyName = $ISOFriendlyName
    } else {
        #We were passed an AutomatedLab.OperatingSystem object
        if ($ALOSFriendlyName) {
            #If a FriendlyName was also passed, use that
            $OSFriendlyName = $ALOSFriendlyName
        }
        else {
            #Otherwise, grab the one from within the AutomatedLab.OperatingSystem object
            $OSFriendlyName = $OperatingSystem.OperatingSystemName
        }
    }

    Invoke-LabCommand -ActivityName "Import Operating System - $OSFriendlyName" -ComputerName $ComputerName -ScriptBlock {
        param  
        (
            #Source Hard drive in the form D:, must be local to the VM
            [Parameter(Mandatory)]
            [string]$OSSourceDrive,

            #Location of the MDT Deployment Share
            [Parameter(Mandatory)]
            [string]$Folder,

            #Friendly Name for the OS as it will appear in deployment workbench and the file system
            [Parameter(Mandatory)]
            [string]$OSFriendlyName
        )

        Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"

        if (!(Get-PSDrive "DS001" -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root $Folder | Out-Null          
        }

        #Create a folder in the deployment share to hold our OS files
        New-Item -path 'DS001:\Operating Systems' -enable 'True' -Name $OSFriendlyName -Comments '' -ItemType 'folder' | Out-Null
        
        #Import the operating system.
        Import-MDTOperatingSystem -path "DS001:\Operating Systems\$OSFriendlyName" -SourcePath "$OSSourceDrive\" -DestinationFolder $OSFriendlyName | Out-Null

        #TEST: See if this resolves the timing issue calling this function in rapid succession
        #SYMPTOM: Only the last set of operating systems are listed in deployment workbench, even though all OS source files are present
        Start-Sleep -Seconds 30
    
    } -ArgumentList $MountedOSImage.DriveLetter, $DeploymentFolder, $OSFriendlyName -PassThru

    Dismount-LabIsoImage -ComputerName $ComputerName
} 

function Import-MDTApplications {
    <#
    .SYNOPSIS
        Imports applications into MDT from a pre-defined XML file
    .DESCRIPTION
        The function performs the following tasks

        1. Opens up the supplied XML file which contains a list of applications to import (structure of the Applications XML file is contained within the example XML file)
        2. Loops through each application in the file
        3. If the file is marked for importing (the XML file can have defined apps that are skipped with the <ImportApp>False</ImportApp> setting)
        4. If the App DownloadPath is defined, attempt to downoad it from the location using Get-LabInternetFile
        5. If no download path was specified, test that the folder as defined in the XML file already exists
        6. Copy the files into the VM C:\Install directory using Copy-LabFileItem with the -Recurse flag set to copy files and sub-folders
        7. Create a folder structure in MDT to hold the app
        8. Import the App
    .EXAMPLE
        PS C:\> Import-MDTApplications -XMLFilePath 'C:\LabSources\MyScripts\MDTApplications.XML' -ComputerName 'MDTServer' -DeploymentFolder 'C:\DeploymentFolder'
        Import apps defined in the 'C:\LabSources\MyScripts\MDTApplications.XML' file to Computer 'MDTServer', and locate the files in 'C:\DeploymentFolder'
    .INPUTS
        [string]$ComputerName - Name of the MDT Server to load the apps into
        [string]$XMlFilePath - Fully qualified name of the XML file containing the applications list
        [string]$DeploymentFolder - Folder within the VM that contains the MDT deployment folder
    .OUTPUTS
        Nil
    .NOTES
        1. A Start-Sleep has been added to pause after each application import.  A race condition was being experienced that meant applications were not being registered correctly
        2. Applications are imported whereby the on-disk file structure under the MDT Deployment Share\Applications is the same as it appears in deployment workbench. This has required a parameter setting under the 
            -DownloadFolder for Import-MDTApplication that includes a subfolder.  This does function correctly, however the Deployment Workbench user interface will NOT allow this (bug in the DW GUI validation)
        2. Feature Enhancement: If an .ISO file is defined on the download path, assume this file should be mounted using Mount-LabIsoImage and files copied from there (good example, Office 2016)
        3. Feature Enhancement: Overloaded verison of this function that can import a single application
    #>

    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$XMLFilePath,
        
        [Parameter(Mandatory)]
        [string]$DeploymentFolder
    )

    [XML]$MDTApps = Get-Content $XMLFilePath
    
    #Download the files referenced in the XML File, copy and install
    ForEach ($App in $MDTApps.Applications.Application)
    {
        #Check if the App Should be Installed to the MDT Server
        If ($App.ImportApp -eq "True") {
            #Set the base path for downloaded apps to be in the SoftwarePackages Folder
            $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
            $downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath $App.AppPath
            $downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath $App.Name

            if (!([string]::IsNullOrEmpty($App.DownloadPath)))
            {
                #Assume the file needs to be downloaded from the internet 
                New-Item -Path "$downloadTargetFolder" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                Get-LabInternetFile -Uri $App.DownloadPath -Path $downloadTargetFolder -ErrorAction Stop    
            }
            else {
                #No Download Path Specified, check to make sure the root folder exists
                if (!(Test-Path -Path $downloadTargetFolder)){
                    #Error, couldnt locate the source directory, throw error
                    Write-LogFunctionExitWithError -Message "Application '$($App.Name)' not located at $downloadTargetFolder, exiting"
                    return
                }
            }

            #Copy the newly downloaded file into the VM, retaining the same directory structure
            $destinationFolderName = Join-Path -Path 'C:\Install' -ChildPath $App.AppPath
            Copy-LabFileItem -Path $downloadTargetFolder -DestinationFolderPath $destinationFolderName -ComputerName $ComputerName -Recurse

            Invoke-LabCommand -ActivityName "Import $($App.Name) to MDT" -ComputerName $ComputerName -ScriptBlock {
                param  
                (
                    [Parameter(Mandatory)]
                    $App,

                    [Parameter(Mandatory)]
                    $Folder
                )
       
                #Which folder contains the source content
                $SourcePath = Join-Path -Path 'C:\Install' -ChildPath $App.AppPath
                $SourcePath = Join-Path -Path $SourcePath -ChildPath $App.Name
            
                Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
            
                #Establish a connection to the Deployment Folder
                if (!(Get-PSDrive "DS001" -ErrorAction SilentlyContinue)) {
                    New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root $Folder | Out-Null        
                }
            
                #Set up the App Working Directory and Destination
                $AppWorkingDirectory = ".\Applications\$($App.AppPath)\$($App.Name)"
                $AppDestinationFolder = "$($App.AppPath)\$($App.Name)"
 
                #Create a folder in the deployment share to hold the Application group
                New-Item -path 'DS001:\Applications' -enable 'True' -Name $($App.AppPath) -Comments '' -ItemType 'folder' -ErrorAction SilentlyContinue | Out-Null

                #Actually Import the application into MDT
                Import-MDTApplication -path "DS001:\Applications\$($App.AppPath)" -enable "True" -Name $($App.Name) -ShortName $($App.ShortName) -Version $($App.Version) -Publisher $($App.Publisher) -Language $($App.Language) -CommandLine $($App.CommandLine) -WorkingDirectory $AppWorkingDirectory -ApplicationSourcePath $SourcePath -DestinationFolder $AppDestinationFolder | Out-Null

                #Sleep between importing applications, otherwise apps dont get written to the Applications.XML file correctly
                Start-Sleep -Seconds 10
            
            } -ArgumentList $App, $DeploymentFolder -PassThru   

        } else {
            #Asked to not import the application, write a message to the screen
            Write-ScreenInfo "Application '$($App.Name)' not being imported"
        }

    }
    
}

function Install-MDT {
    <#
    .SYNOPSIS
       This function installed the main ADK and MDT executables, and configures MDT
    .DESCRIPTION
       This function performs the following tasks:
   
       1. Downloads the MDT binaries from the Internet (if Required)
       2. Copies the binaries for the ADK and MDT to the server
       3. Installs ADK and MDT
       4. Installs the WDS Role
       5. Creates the Deployment Folder and Share
       6. Configures Settings.XML to add additional options into boot image
       7. Configures Bootstrap.ini file with default settings to connect to deployment Server
       8. Generated MDT Boot images
       9. Initialises WDS in standalone server mode
       10. Imports MDT boot images into WDS 
    .EXAMPLE
       Install-MDT -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -DeploymentShare 'C:\DeploymentShare' -AdminUserID 'Administrator' -AdminPassword 'Somepass1'
       Installs MDT and ADK onto the server called 'MDTServer', and configures the deployment share to be in 'C:\DeploymentShare' with a share name of 'DeploymentShare$'
       Admin password to allow Windows PE to autoconnect to the MDT Share is Administrator, SomePass1
    .INPUTS
       [string]$ComputerName - Name of the MDTServer prepared using AL
       [string]$DeploymentFolder - Fully Qualified path to house the deployment folder, directory will be created if it does not exist
       [string]$DeploymentShare - Share name to be created that points to the root of the deployment folder. Used by clients when deploying via settings in Bootstrap.ini
       [string]$InstallUserID - Name of an account that has rights to access the MDT Share - added to bootstrap.ini to allow auto logon for Windows PE.
                                If account does not exist on the local machine, it will be created.
       [string]$InstallPassword - Password for the above account in cleartext
    .OUTPUTS
       Nil Output
    .NOTES
       1. ADK must be downloaded manually, and placed in a subfolder called ADK within $labsources\SoftwarePackages. The function checks for the existence of the folder
            and errors out if it is not found. Due to ADK requiring a bootstrap download and then seperate packages download, the AL Get-LabInternetFile is not directly usable for this task (unless I'm mistaken)
       2. MDT Install files are downloaded from the referenced $MDTDownloadLocation URL, if new version of MDT is released, this URL will need to be changed (Tested with version 8450 released 22/12/17, URL didnt change from v8443)
       3. As at AL 4.5.0 - Install-LabWindowsFeature does not support a -IncludeManagementTools switch, hence .NET is installed using the AL cmdlet as it mounts the ISO to access
            the correct files. WDS is installed using a standard Invoke-LabCommand to allow the -IncludeManagementTools switch to be passed
       4. Start-Sleep commands are in the code to prevent some race conditions that occured during development.  Later fix to find the specific wait condition (ie service startup) and build more smarts into routine
    #>
       param(
           [Parameter(Mandatory)]
           [string]$ComputerName,
           
           [Parameter(Mandatory)]
           [string]$DeploymentFolder,
   
           [Parameter(Mandatory)]
           [string]$DeploymentShare,

           [Parameter(Mandatory, HelpMessage="Install Account Name cannot be blank")]
           [ValidateNotNullOrEmpty()]
           [string]$InstallUserID,
   
           [Parameter(Mandatory, HelpMessage="Install Account Password cannot be blank")]
           [ValidateNotNullOrEmpty()]
           [string]$InstallPassword
       )
   
       $MDTDownloadLocation = 'https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi'
   
       #Bring all available disks online (this is to cater for the situation a secondary drive has been specified in the machine configuration)
       #For some reason, cant make the disk online and RW in the one command, need to perform two seperate actions
       Invoke-LabCommand -ActivityName 'Bring Disks Online' -ComputerName $ComputerName -ScriptBlock {
           $DataVolume = Get-Disk | Where-Object -Property OperationalStatus -eq Offline
           $DataVolume | Set-Disk -IsOffline $false
           $DataVolume | Set-Disk -IsReadOnly $false
       }
   
       $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
   
       #Check for existance of ADK Installation Files
       if (!(Test-Path -Path (Join-Path -Path $downloadTargetFolder -ChildPath 'ADK'))) {
           Write-LogFunctionExitWithError -Message "ADK Installation files not located at '$(Join-Path -Path $downloadTargetFolder -ChildPath 'ADK')'"
           return
       }
       
       Write-ScreenInfo -Message "Downloading MDT Installation Files from '$MDTDownloadLocation'"
       Get-LabInternetFile -Uri $MDTDownloadLocation -Path $downloadTargetFolder -ErrorAction Stop
   
       $MDTDownloadURL = New-Object System.Uri($MDTDownloadLocation)
       $MDTInstallFileName = $MDTDownloadURL.Segments[$MDTDownloadURL.Segments.Count-1]
   
       Write-ScreenInfo "Copying MDT Install Files to server $ComputerName..."
       Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $MDTInstallFileName) -DestinationFolderPath C:\Install -ComputerName $ComputerName
   
       Write-ScreenInfo "Copying ADK Install Files to server $ComputerName..."
       Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath 'ADK') -DestinationFolderPath C:\Install -ComputerName $ComputerName -Recurse
   
       Write-ScreenInfo "Installing ADK on server '$ComputerName'..."
       Invoke-LabCommand -ActivityName 'Install ADK' -ComputerName $ComputerName -ScriptBlock {
           Start-Process -FilePath "C:\Install\ADK\adksetup.exe" -ArgumentList "/norestart /q /ceip off /features OptionId.WindowsPreinstallationEnvironment OptionId.DeploymentTools OptionId.UserStateMigrationTool OptionId.ImagingAndConfigurationDesigner" -Wait
       }
   
       Install-LabWindowsFeature -ComputerName $ComputerName -FeatureName 'NET-Framework-Core'
   
       Invoke-LabCommand -ActivityName 'Install WDS Tools' -ComputerName $ComputerName -ScriptBlock {
           Add-WindowsFeature WDS -IncludeManagementTools | Out-Null
       }
   
       Write-ScreenInfo "Installing 'MDT' on server $ComputerName..."
       Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "C:\Install\$MDTInstallFileName" -CommandLine '/qb'
   
       Invoke-LabCommand -ActivityName 'Configure MDT' -ComputerName $ComputerName -ScriptBlock {
           param  
           (
               [Parameter(Mandatory)]
               $Folder,
   
               [Parameter(Mandatory)]
               $Share,

               [Parameter(Mandatory)]
               [string]$InstallUserID,
   
               [Parameter(Mandatory)]
               [string]$InstallPassword
   
           )

           if (!(Get-LocalUser -Name $InstallUserID -ErrorAction SilentlyContinue)) {
                #Account doesnt exist on the machine, create it.    
                New-LocalUser -Name $InstallUserID -Password ($InstallPassword | ConvertTo-SecureString -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
           }   
   
           #Create Folder for Deployment Share
           if (!(Get-Item -Path $Folder -ErrorAction SilentlyContinue)) {
               New-Item -Path $Folder -Type Directory | Out-Null
           }

           #Create MDT Deployment Share
           if (!(Get-SmbShare -Name $Share -ErrorAction SilentlyContinue)) {
               New-SmbShare –Name $Share –Path $Folder –ChangeAccess EVERYONE | Out-Null
           }

           Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
           
           if (!(Get-PSDrive "DS001" -ErrorAction SilentlyContinue)) {
               New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root $Folder  | Out-Null        
           }
   
           #Configure Settings for WINPE Image prior to generating
           $settings = "$Folder\Control\Settings.xml"
           $xml = [xml](Get-Content $settings)
           $xml.Settings.Item("Boot.x86.FeaturePacks")."#text" = "winpe-mdac,winpe-netfx,winpe-powershell,winpe-wmi,winpe-hta,winpe-scripting"
           $xml.Settings.Item("Boot.x64.FeaturePacks")."#text" = "winpe-mdac,winpe-netfx,winpe-powershell,winpe-wmi,winpe-hta.winpe-scripting"
           $xml.Save($settings)
   
           #Set up the BOOTSTRAP.INI file so we dont get prompted for passwords to connect to the share and the like.
           #Note: Need to do this before we generate the images, as the bootstrap.INI file ends up in the Boot Image.
           #Discussion of avialble bootstrap.ini settings is located in the MDT toolkit reference at:
           # https://technet.microsoft.com/en-us/library/dn781091.aspx
           $File = Get-Content -Path "$Folder\Control\BootStrap.ini"
           $File += "DeployRoot=\\$ENV:COMPUTERNAME\$Share"
           $File += $("UserDomain=$ENV:COMPUTERNAME")
           $File += $("UserID=$InstallUserID")
           $File += $("UserPassword=$InstallPassword")
           $File += "SkipBDDWelcome=YES"
           $File | Out-File -Encoding ascii -FilePath "$Folder\Control\BootStrap.ini"           
           
           #This process will force generation of the Boot Images
           Update-MDTDeploymentShare -Path "DS001:" -Force
   
           Start-Sleep -Seconds 10
   
           #Configure WDS
           Start-Process -FilePath "C:\Windows\System32\WDSUTIL.EXE" -ArgumentList "/Verbose /Initialize-Server /RemInst:C:\RemoteInstall /StandAlone" -Wait
   
           #Wait for WDS to Start up
           Start-Sleep -Seconds 10
           
           #Once WDS is complete, pull in the boot images generated by MDT
           Import-WDSBootimage -Path $($Folder + "\Boot\LiteTouchPE_x64.wim") -NewImageName 'LiteTouch PE (x64)' -SkipVerify | Out-Null
           Import-WDSBootimage -Path $($Folder + "\Boot\LiteTouchPE_x86.wim") -NewImageName 'LiteTouch PE (x86)' -SkipVerify | Out-Null
   
           Start-Sleep -Seconds 10
           
       }  -ArgumentList $DeploymentFolder, $DeploymentShare, $InstallUserID, $InstallPassword -PassThru

}

#Cleanup from last run
Remove-Item -Path 'C:\Temp\MDTLab.log' -Force -ErrorAction SilentlyContinue
Start-Transcript -Path 'C:\Temp\MDTLab.log'

New-LabDefinition -Name 'MDTLab' -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name 'MDTLab' -AddressSpace 192.168.50.0/24

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path


#Example with a secondary disk to hold the MDT Install Files
$DeploymentFolderLocation = 'D:\DeploymentShare'
Add-LabDiskDefinition -Name MDTData -DiskSizeInGb 60
#Add-LabMachineDefinition -Name MDTServer -DiskName MDTData -Memory 4GB -Processors 4 -OperatingSystem 'Windows Server 2012 R2 SERVERSTANDARD' -IpAddress '192.168.50.10'
Add-LabMachineDefinition -Name MDTServer -DiskName MDTData -Memory 4GB -Processors 4 -OperatingSystem 'Windows Server 2016 SERVERSTANDARD' -IpAddress '192.168.50.10'

#Example using a standard, single drive server
#$DeploymentFolderLocation = 'C:\DeploymentShare'
#Add-LabMachineDefinition -Name MDTServer -Memory 4GB -Processors 4 -OperatingSystem 'Windows Server 2012 R2 SERVERSTANDARD' -IpAddress '192.168.50.10'

#Do the normal AL deployment goodness
Install-Lab

#Installs MDT and performs majority of configuration
Install-MDT -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -DeploymentShare 'DeploymentShare$' -InstallUserID 'svcInstaller' -InstallPassword 'Pass@word1'
#At this stage, MDT and WDS are installed and configured, however there are NO Operating Systems or applications available, plus DHCP still needs to be installed and configured

#Import applications into MDT (optional step). The example below uses an XML file containg the app information
Import-MDTApplications -XMLFilePath $(Join-Path -Path $ScriptDir -ChildPath 'MDTApplications.XML') -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation

#EXAMPLES:
#Standard Import from ISO
#Import-MDTOS -ComputerName 'MDTServer' -ISOPath 'C:\LabSources\ISOs\SW_DVD5_WIN_ENT_10_1511_64BIT_English_MLF_X20-82288.ISO' -ISOFriendlyName 'Windows 10 1511' -DeploymentFolder $DeploymentFolderLocation

#Import from AL OS Object using default description
#Import-MDTOS -ComputerName 'MDTServer' -OperatingSystem ((Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows Server 2012 R2 SERVERSTANDARD'}) | Select-Object -First 1) -DeploymentFolder $DeploymentFolderLocation

#Import from AL OS Object using supplied friendly name
#Import-MDTOS -ComputerName 'MDTServer' -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows 7 PROFESSIONAL'}) -ALOSFriendlyName "Windows 7"  -DeploymentFolder $DeploymentFolderLocation


Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows 10*' -and  $_.Version -eq '10.0.10586.0'}) -ALOSFriendlyName 'Windows 10 1511'
Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows 10 Enterprise' -and  $_.Version -eq '10.0.14393.0'}) -ALOSFriendlyName 'Windows 10 1607'
Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows 10*' -and  $_.Version -eq '10.0.15063.296'}) -ALOSFriendlyName 'Windows 10 1703'
Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows 10 Enterprise 2016 LTSB Evaluation'}) -ALOSFriendlyName 'Windows 10 LTSB 2016'
Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows Server 2012 R2 SERVERSTANDARD'}) -ALOSFriendlyName 'Windows Server 2012 R2'
Import-MDTOS -ComputerName 'MDTServer' -DeploymentFolder $DeploymentFolderLocation -OperatingSystem (Get-LabAvailableOperatingSystem | Where-Object {$_.OperatingSystemName -like 'Windows Server 2016 SERVERSTANDARD'}) -ALOSFriendlyName 'Windows Server 2016'

#Install and activate DHCP and bind to the Ethernet adapter. This has been split out as it needs a bit more work if a lab is deployed with a domain controller with DHCP already available, and DHCP servers for domains require authorisation.
#This version of the routine assumes that DHCP needs to be installed and configured on the MDT server, along with fixing up WDS to listen correctly on a machine with DHCP.
#Note: No checking currently if the supplied DHCP scope ranges fall correctly within the AL network definition.
Install-MDTDHCP -ComputerName 'MDTServer' -DHCPScopeName 'Default Scope for DHCP' -DHCPscopeDescription 'Default Scope' -DHCPScopeStart 192.168.50.100 -DHCPScopeEnd 192.168.50.110 -DHCPScopeMask 255.255.255.0

#We now have a working MDT Server ready for deployment, only remaining manual activity is to create a task sequence in Deployment Workbench
#To use MDT, simply create a standard (NON AL) virtual machine, and bind the NIC to the AL Created Virtual Switch, and boot the machine to PXE.

Show-LabDeploymentSummary -Detailed

Stop-Transcript



