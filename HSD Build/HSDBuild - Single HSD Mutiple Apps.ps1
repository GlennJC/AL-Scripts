<#
This is an example lab using AL that performs the folliwng activites:
    1. Creates a single DC and RDS Session Host
    2. Uses AutomationLab to build the Lab Machines
    3. Installs RemoteDesktop Services
    4. Publishes the standard wordpad application
    5. Installs Firefox via an internet download, and Publishes the application
    6. Installs a VL edition of Office 2016 and Publishes Word and Excel

    Note: VL Editions of Office are required as non-VL editions immediately raise errors on Session Hosts regarding an unsupported configuration (licensing issue essentially)
#>

$oldverbose = $VerbosePreference
$VerbosePreference = 'continue'

#Import the RDS mode, assumed to be in the same directory as this script
Import-Module .\InstallRDS.psm1

$labName = 'HSDModularLab'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.70.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'hsdlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.70.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}

Add-LabMachineDefinition -Name MOD-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.70.10'
#Add a host that will run all the roles.  Since we want to demonstrate both published desktops and apps, install Office
Add-LabMachineDefinition -Name MOD-HSD1 -Memory 4GB -IPAddress '192.168.70.20' 

#Do the AL Installation goodness
Install-Lab

#Install Remote Desktop Services in Session Deployment Mode
Install-RDS -ConnectionBroker (Get-LabMachine -ComputerName 'MOD-HSD1') -WebAccessServer (Get-LabMachine -ComputerName 'MOD-HSD1') -SessionHost (Get-LabMachine -ComputerName 'MOD-HSD1') -LicensingServer (Get-LabMachine -Role 'RootDC') -SessionDeployment

#Publish the Wordpad executable built into all Servers
Publish-RDSApplication -Alias 'WordPad' -DisplayName 'WordPad' -FilePath "C:\Program Files\Windows NT\Accessories\wordpad.exe" -ConnectionBroker (Get-LabMachine -ComputerName 'MOD-HSD1')     

#Install Firefox onto the Session Server, and publish the firefox app
Install-RDSApplication -SessionHost (Get-LabMachine -ComputerName 'MOD-HSD1') -URL 'https://ftp.mozilla.org/pub/firefox/releases/57.0/win64/en-US/Firefox%20Setup%2057.0.exe' -InstallArguments '-ms'
Publish-RDSApplication -Alias 'FireFox' -DisplayName 'FireFox' -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe" -ConnectionBroker (Get-LabMachine -ComputerName 'MOD-HSD1')     

#Install VL Edition of Office Professional Plus 2016 onto the Server, and Publish Word + Excel
Install-RDSApplication -SessionHost (Get-LabMachine -ComputerName 'MOD-HSD1') -DirectoryPath "$labSources\SoftwarePackages\Microsoft Office Pro Plus 2016" -InstallExecutable "Microsoft Office Pro Plus 2016\Setup.exe" -InstallArguments "/adminfile Office_R2.MSP"
Publish-RDSApplication -Alias 'Microsoft Word' -DisplayName 'Microsoft Word' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\WINWORD.EXE" -ConnectionBroker (Get-LabMachine -ComputerName 'MOD-HSD1')     
Publish-RDSApplication -Alias 'Microsoft Excel' -DisplayName 'Microsoft Excel' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\EXCEL.EXE" -ConnectionBroker (Get-LabMachine -ComputerName 'MOD-HSD1')     

#Republish the Full Desktop into the web access site (defaults to off)
Publish-RDSDesktop -SessionHost (Get-LabMachine -ComputerName 'MOD-HSD1') 
       
Show-LabDeploymentSummary -Detailed

$VerbosePreference = $oldverbose
