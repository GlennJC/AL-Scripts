$oldverbose = $VerbosePreference
$VerbosePreference = 'silentlycontinue'

#Routine to install and application into a AL-Deployed Virtual Machine
#This function is a wrapper around the standard AL routines, and supports single files, directories, and ISO files as the input source
function Install-Application {

    param (
       
        #Hosts to install the application on
        [Parameter(Mandatory)]
        [AutomatedLab.Machine[]]$ComputerName,

        #URL for the application to be downloaded
        [Parameter(ParameterSetName='ByURL')]
        [string]$URL,

        #ISO Path for the installation ISO
        [Parameter(ParameterSetName='ByISO')]
        [string]$ISOPath,

        #Folder where existing installation files are located
        [Parameter(ParameterSetName='ByPath')]
        [string]$DirectoryPath,

        #Path relative to source media where installation executable is located. If a URL was provided, it is assumed the InstallExecutable is the last segment in the URL name
        [parameter(Mandatory, ParameterSetName='ByISO')]
        [parameter(Mandatory, ParameterSetName='ByPath')]
        [ValidateNotNullOrEmpty()]
        [string]$InstallExecutable,

        #Required arguments for the installation
        [string]$InstallArguments
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ByURL' {
            #We were passed a URL of the application to install, download if necessary
            $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
            $internalUri = New-Object System.Uri($URL)
            Get-LabInternetFile -Uri $internalUri -Path $downloadTargetFolder -ErrorAction Stop 
            $DownloadedFileName = $internalUri.Segments[$internalUri.Segments.Count-1]
            Write-ScreenInfo 'Copying source files to Target Server(s)' -TaskStart
            Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $DownloadedFileName) -DestinationFolderPath C:\Install -ComputerName $ComputerName
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "C:\Install\$DownloadedFileName" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
        }
        'ByPath' {
            Write-ScreenInfo 'Copying source directories to Target Server(s)' -TaskStart
            Copy-LabFileItem -Path $DirectoryPath -DestinationFolderPath 'C:\Install' -ComputerName $ComputerName -Recurse 
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd
            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "C:\Install\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
        }
        'ByISO' {
            Write-ScreenInfo 'Mounting ISO on target server(s)' -TaskStart
            $disk = Mount-LabIsoImage -ComputerName $ComputerName -IsoPath $ISOPath -PassThru -SupressOutput
            Write-ScreenInfo 'Finished' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "$($disk.DriveLetter)\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
            Dismount-LabIsoImage -ComputerName $ComputerName -SupressOutput
    
        }
    }
    
}

$oldverbose = $VerbosePreference
$VerbosePreference = 'continue'

$labName = 'CitrixLab'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "D:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.70.0/24

Add-LabIsoImageDefinition -Name 'XenDesktop7.15' -Path 'C:\LabSources\ISOs\XenApp_and_XenDesktop_7_15.iso'

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'citrixlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.70.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

Add-LabMachineDefinition -Name CTX-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.70.10'
#Citrix Server - Will hold all Citrix Roles
Add-LabMachineDefinition -Name CTX-AP01 -Memory 4GB -IPAddress '192.168.70.20' 
#XenApp Server, will run user applications
Add-LabMachineDefinition -Name CTX-XA01 -Memory 4GB -IPAddress '192.168.70.21' 
#XenDesktop Static Workstation
Add-LabMachineDefinition -Name CTX-XD01 -Memory 4GB -IPAddress '192.168.70.30' -OperatingSystem 'Windows 10 Enterprise'

#Do the AL Installation goodness
Install-Lab

#Install FireFox and Office onto the machines.
$HostList = @()
$HostList += (Get-LabMachine -ComputerName 'CTX-XA01')
$HostList += (Get-LabMachine -ComputerName 'CTX-XD01')

Install-Application -ComputerName $HostList -URL 'https://download-installer.cdn.mozilla.net/pub/firefox/releases/57.0.4/win64/en-US/Firefox Setup 57.0.4.exe' -InstallArguments '-ms'
Install-Application -ComputerName $HostList -DirectoryPath "$labSources\SoftwarePackages\Microsoft Office Pro Plus 2016" -InstallExecutable "Microsoft Office Pro Plus 2016\Setup.exe" -InstallArguments "/adminfile Office_R2.MSP"

$disk = Mount-LabIsoImage -ComputerName 'CTX-AP01' -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'XenDesktop7.15'}).Path -PassThru -SupressOutput
#$job=Install-LabSoftwarePackage -ComputerName 'CTX-AP01'-LocalPath "$($disk.DriveLetter)\x64\XenDesktop Setup\XenDesktopServerSetup.exe" -CommandLine '/xenapp /configure_firewall /noreboot /quiet' -AsJob -PassThru -ErrorAction Stop -Timeout 20
#$result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop

            
Show-LabDeploymentSummary -Detailed

$VerbosePreference = $oldverbose