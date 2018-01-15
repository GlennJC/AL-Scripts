function Install-Application {

    param (
       
        #Session hosts to install the application on
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
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$InstallArguments,

        [parameter(ParameterSetName='ByISO')]
        [parameter(ParameterSetName='ByPath')]
        [switch]$NoCopy
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ByURL' {
            #We were passed a URL of the application to install, download if necessary
            $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
            $internalUri = New-Object System.Uri($URL)
            Get-LabInternetFile -Uri $internalUri -Path $downloadTargetFolder -ErrorAction Stop 
            $DownloadedFileName = $internalUri.Segments[$internalUri.Segments.Count-1]
            Write-ScreenInfo 'Copying source files to Target Servers' -TaskStart
            Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $DownloadedFileName) -DestinationFolderPath C:\Install -ComputerName $ComputerName
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $ComputerName -LocalPath "C:\Install\$DownloadedFileName" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
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
    
}

$oldverbose = $VerbosePreference
$VerbosePreference = 'silentlycontinue'

$labName = 'CitrixLab'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.70.0/24

Add-LabIsoImageDefinition -Name 'XenDesktop7.15' -Path 'C:\LabSources\ISOs\XenApp_and_XenDesktop_7_15.iso'

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'citrixlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.70.10'
    'Add-LabMachineDefinition:Processors' =  '2'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

Add-LabMachineDefinition -Name CTX-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.70.10'
#Citrix Server - Will hold all Citrix Roles
Add-LabMachineDefinition -Name CTX-AP01 -Memory 4GB -Roles SQLServer2014 -IPAddress '192.168.70.20' 
#XenApp Server, will run user applications
# Add-LabMachineDefinition -Name CTX-XA01 -Memory 4GB -IPAddress '192.168.70.21' 
# #XenDesktop Static Workstation
# Add-LabMachineDefinition -Name CTX-XD01 -Memory 4GB -IPAddress '192.168.70.30' -OperatingSystem 'Windows 10 Enterprise'

#Do the AL Installation goodness
Install-Lab

#Save a snapshot of the machines during development, remove for production deployments
Checkpoint-LABVM -All -SnapshotName 'After Build'

#Install the necessary Windows Features for the main citrix server
Install-LabWindowsFeature -ComputerName 'CTX-AP01' -FeatureName 'NET-Framework-45-Core,GPMC,RSAT-ADDS-Tools,RDS-Licensing-UI,WAS,WAS-Process-Model,WAS-Config-APIs,Telnet-Client,Remote-Assistance,File-Services,FS-FileServer'
Restart-LABVM -ComputerName 'CTX-AP01' -Wait

$CitrixHost = (Get-LabMachine -ComputerName 'CTX-AP01')
Install-LabWindowsFeature -ComputerName $CitrixHost -FeatureName 'Web-Server,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Health,Web-Http-Logging,Web-Log-Libraries,Web-Http-Tracing'
Install-LabWindowsFeature -ComputerName $CitrixHost -FeatureName 'Web-Performance' -IncludeAllSubFeature
Install-LabWindowsFeature -ComputerName $CitrixHost -FeatureName 'Web-Security,Web-Filtering,Web-Basic-Auth,Web-Windows-Auth,Web-App-Dev,Web-AppInit,Web-Net-Ext45,Web-ASP,Web-Asp-Net45,Web-CGI,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Includes'
Install-LabWindowsFeature -ComputerName $CitrixHost -FeatureName 'Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,Web-Lgcy-Mgmt-Console,Web-Lgcy-Scripting,Web-WMI,Web-Scripting-Tools,NET-Framework-45-ASPNET,NET-WCF-HTTP-Activation45'
Restart-LabVM -ComputerName 'CTX-AP01' -Wait

Install-Application -ComputerName $CitrixHost -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2013 Redistributable (x86)" -InstallExecutable "Microsoft Visual C++ 2013 Redistributable (x86)\vcredist_x86.exe" -InstallArguments "/Q"
Install-Application -ComputerName $CitrixHost -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2013 Redistributable (x64)" -InstallExecutable "Microsoft Visual C++ 2013 Redistributable (x64)\vcredist_x64.exe" -InstallArguments "/Q"
Install-Application -ComputerName $CitrixHost -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2015 Redistributable (x64)" -InstallExecutable "Microsoft Visual C++ 2015 Redistributable (x64)\vc_redist.x64.exe" -InstallArguments "/Q"
Install-Application -ComputerName $CitrixHost -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2015 Redistributable (x86)" -InstallExecutable "Microsoft Visual C++ 2015 Redistributable (x86)\vc_redist.x86.exe" -InstallArguments "/Q"
Restart-LabVM -ComputerName 'CTX-AP01' -Wait

$disk = Mount-LabIsoImage -ComputerName 'CTX-AP01' -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'XenDesktop7.15'}).Path -PassThru -SupressOutput
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\Support\SQLLocalDB2014\x64" -InstallExecutable "sqllocaldb.msi" -InstallArguments '/quiet /norestart /log SQLLOCALDB.LOG IACCEPTSQLLOCALDBLICENSETERMS=YES'
Restart-LabVM -ComputerName 'CTX-AP01' -Wait
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\Support\SharedManagementObjects\x86" -InstallExecutable "SQLSysClrTypes.msi" -InstallArguments '/lv "C:\SQLSysClrTypes-x86.log" /quiet INSTALLLOCATION="C:\Program Files\Citrix" ARPSYSTEMCOMPONENT="1" MSIFASTINSTALL="1" MSIRMSHUTDOWN="2" METAINSTALLER="1" CLOUD=False REBOOT=ReallySuppress'
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\Support\SharedManagementObjects\x86" -InstallExecutable "SharedManagementObjects.msi" -InstallArguments '/lv "C:\SharedManagementObjects-x86.log" /quiet INSTALLLOCATION="C:\Program Files\Citrix" ARPSYSTEMCOMPONENT="1" MSIFASTINSTALL="1" MSIRMSHUTDOWN="2" METAINSTALLER="1" CLOUD=False REBOOT=ReallySuppress'
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\Support\SharedManagementObjects\x64" -InstallExecutable "SQLSysClrTypes.msi" -InstallArguments '/lv "C:\SQLSysClrTypes-x64.log" /quiet INSTALLLOCATION="C:\Program Files\Citrix" ARPSYSTEMCOMPONENT="1" MSIFASTINSTALL="1" MSIRMSHUTDOWN="2" METAINSTALLER="1" CLOUD=False REBOOT=ReallySuppress'
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\Support\SharedManagementObjects\x64" -InstallExecutable "SharedManagementObjects.msi" -InstallArguments '/lv "C:\SharedManagementObjects-x64.log" /quiet INSTALLLOCATION="C:\Program Files\Citrix" ARPSYSTEMCOMPONENT="1" MSIFASTINSTALL="1" MSIRMSHUTDOWN="2" METAINSTALLER="1" CLOUD=False REBOOT=ReallySuppress'
Restart-LabVM -ComputerName 'CTX-AP01' -Wait

#Install the Main Citrix XenDesktop Components
Install-Application -ComputerName $CitrixHost -NoCopy -DirectoryPath "$($disk.DriveLetter)\x64\XenDesktop Setup" -InstallExecutable "XenDesktopServerSetup.exe" -InstallArguments '/configure_firewall /noreboot /quiet'
Restart-LabVM -ComputerName 'CTX-AP01' -Wait



#The the necessary apps installed on the machines

# $InstallHosts = @()
# $InstallHosts += (Get-LabMachine -ComputerName 'CTX-XA01')
# $InstallHosts += (Get-LabMachine -ComputerName 'CTX-XD01')

# #Install Office VL Edition on both the XA and XD machines
# Install-Application -ComputerName $InstallHosts -URL 'https://ftp.mozilla.org/pub/firefox/releases/57.0/win64/en-US/Firefox%20Setup%2057.0.exe' -InstallArguments '-ms'
# Install-Application -ComputerName $InstallHosts -DirectoryPath "$labSources\SoftwarePackages\Microsoft Office Pro Plus 2016" -InstallExecutable "Microsoft Office Pro Plus 2016\Setup.exe" -InstallArguments "/adminfile Office_R2.MSP"

# #Install the compontents required on the XenApp host
# Install-LabWindowsFeature -ComputerName 'CTX-XA01' -FeatureName 'Remote-Desktop-Services,RDS-RD-Server,NET-Framework-45-Core,Remote-Assistance'
# Restart-LabVM -ComputerName 'CTX-XA01' -Wait

#Install the Visual C++ Runtimes
# Install-Application -ComputerName (Get-LabMachine -ComputerName 'CTX-XA01') -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2013 Redistributable (x86)" -InstallExecutable "Microsoft Visual C++ 2013 Redistributable (x86)\vcredist_x86.exe" -InstallArguments "/Q"
# Install-Application -ComputerName (Get-LabMachine -ComputerName 'CTX-XA01') -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2013 Redistributable (x64)" -InstallExecutable "Microsoft Visual C++ 2013 Redistributable (x64)\vcredist_x64.exe" -InstallArguments "/Q"
# Install-Application -ComputerName (Get-LabMachine -ComputerName 'CTX-XA01') -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2015 Redistributable (x64)" -InstallExecutable "Microsoft Visual C++ 2015 Redistributable (x64)\vc_redist.x64.exe" -InstallArguments "/Q"
# Install-Application -ComputerName (Get-LabMachine -ComputerName 'CTX-XA01') -DirectoryPath "$labSources\SoftwarePackages\Frameworks\Microsoft Visual C++ 2015 Redistributable (x86)" -InstallExecutable "Microsoft Visual C++ 2015 Redistributable (x86)\vc_redist.x86.exe" -InstallArguments "/Q"
# Restart-LabVM -ComputerName 'CTX-XA01' -Wait

# $disk = Mount-LabIsoImage -ComputerName 'CTX-XA01' -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'XenDesktop7.15'}).Path -PassThru -SupressOutput
# $job=Install-LabSoftwarePackage -ComputerName 'CTX-XA01'-LocalPath "$($disk.DriveLetter)\x64\XenDesktop Setup\XenDesktopVDASetup.exe" -CommandLine '/quiet /noreboot /components vda,plugins /controllers ""CTX-AP01.citrixlab.local"" /enable_hdx_ports /enable_remote_assistance' -AsJob -PassThru -ErrorAction Stop
# $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop

# $disk = Mount-LabIsoImage -ComputerName 'CTX-XD01' -ISOPath (Get-LabIsoImageDefinition | Where-Object { $_.Name -eq 'XenDesktop7.15'}).Path -PassThru -SupressOutput
# $job=Install-LabSoftwarePackage -ComputerName 'CTX-XD01'-LocalPath "$($disk.DriveLetter)\x64\XenDesktop Setup\XenDesktopVDASetup.exe" -CommandLine '/quiet /noreboot /components vda,plugins /controllers ""CTX-AP01.citrixlab.local"" /enable_hdx_ports /enable_remote_assistance /remotepc' -AsJob -PassThru -ErrorAction Stop
# $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop

Show-LabDeploymentSummary -Detailed

$VerbosePreference = $oldverbose