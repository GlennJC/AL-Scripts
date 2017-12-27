<#
This is an example lab using AL that performs the following activites:
    1. Creates a single DC and Multiple RDS Session Host lab
    2. Uses AutomationLab to build the Lab Machines
    3. Installs RemoteDesktop Services
    4. Publishes the Full Desktop
#>

$oldverbose = $VerbosePreference
$VerbosePreference = 'silentlycontinue'

#Import the RDS mode, assumed to be in the same directory as this script
Import-Module .\InstallRDS.psm1

$labName = 'HSDMultiHost'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.50.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'hsdminlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.50.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

Add-LabMachineDefinition -Name MUL-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.50.10'
#Add a host that will run all the roles.
Add-LabMachineDefinition -Name MUL-HSD1 -Memory 2GB -IPAddress '192.168.50.20' 
Add-LabMachineDefinition -Name MUL-HSD2 -Memory 2GB -IPAddress '192.168.50.21' 
Add-LabMachineDefinition -Name MUL-HSD3 -Memory 2GB -IPAddress '192.168.50.22' 
Add-LabMachineDefinition -Name MUL-HSD4 -Memory 2GB -IPAddress '192.168.50.23' 

#Do the AL Installation goodness
Install-Lab

$SessionHostList = @()
$SessionHostList += (Get-LabMachine -ComputerName 'MUL-HSD1')
$SessionHostList += (Get-LabMachine -ComputerName 'MUL-HSD2')
$SessionHostList += (Get-LabMachine -ComputerName 'MUL-HSD3')
$SessionHostList += (Get-LabMachine -ComputerName 'MUL-HSD4')

#Install Remote Desktop Services in Session Deployment Mode
Install-RDS -ConnectionBroker (Get-LabMachine -ComputerName 'MUL-HSD1') -WebAccessServer (Get-LabMachine -ComputerName 'MUL-HSD1') -SessionHost $SessionHostList -LicensingServer (Get-LabMachine -Role 'RootDC') -SessionDeployment

Install-RDSApplication -SessionHost $SessionHostList -URL 'https://ftp.mozilla.org/pub/firefox/releases/57.0/win64/en-US/Firefox%20Setup%2057.0.exe' -InstallArguments '-ms'
Publish-RDSApplication -Alias 'FireFox' -DisplayName 'FireFox' -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe" -ConnectionBroker (Get-LabMachine -ComputerName 'MUL-HSD1')     

Install-RDSApplication -SessionHost $SessionHostList -DirectoryPath "$labSources\SoftwarePackages\Microsoft Office Pro Plus 2016" -InstallExecutable "Microsoft Office Pro Plus 2016\Setup.exe" -InstallArguments "/adminfile Office_R2.MSP"
Publish-RDSApplication -Alias 'Microsoft Word' -DisplayName 'Microsoft Word' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\WINWORD.EXE" -ConnectionBroker (Get-LabMachine -ComputerName 'MUL-HSD1')     
Publish-RDSApplication -Alias 'Microsoft Excel' -DisplayName 'Microsoft Excel' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\EXCEL.EXE" -ConnectionBroker (Get-LabMachine -ComputerName 'MUL-HSD1')     

#Republish the Full Desktop into the web access site (turns off once apps are published)
Publish-RDSDesktop -ConnectionBroker (Get-LabMachine -ComputerName 'MUL-HSD1') 

Show-LabDeploymentSummary -Detailed

$VerbosePreference = $oldverbose
