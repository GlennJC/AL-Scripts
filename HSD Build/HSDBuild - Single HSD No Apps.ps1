<#
This is an example lab using AL that performs the folliwng activites:
    1. Creates a single DC and RDS Session Host
    2. Uses AutomationLab to build the Lab Machines
    3. Installs RemoteDesktop Services
    4. Publishes the Full Desktop
#>

$oldverbose = $VerbosePreference
$VerbosePreference = 'continue'

#Import the RDS mode, assumed to be in the same directory as this script
Import-Module .\InstallRDS.psm1

$labName = 'HSDMinimal'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.60.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'hsdminlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.60.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

Add-LabMachineDefinition -Name MIN-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.60.10'
#Add a host that will run all the roles.
Add-LabMachineDefinition -Name MIN-HSD1 -Memory 4GB -IPAddress '192.168.60.20' 

#Do the AL Installation goodness
Install-Lab

#Install Remote Desktop Services in Session Deployment Mode
Install-RDS -ConnectionBroker (Get-LabMachine -ComputerName 'MIN-HSD1') -WebAccessServer (Get-LabMachine -ComputerName 'MIN-HSD1') -SessionHost (Get-LabMachine -ComputerName 'MIN-HSD1') -LicensingServer (Get-LabMachine -Role 'RootDC') -SessionDeployment

#Republish the Full Desktop into the web access site so at least there is something to test (defaults to off)
Publish-RDSDesktop -SessionHost (Get-LabMachine -ComputerName 'MIN-HSD1') 
       
Show-LabDeploymentSummary -Detailed

$VerbosePreference = $oldverbose
