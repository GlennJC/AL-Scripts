
$labName = 'HSDLabMinimal'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.60.0/24
Add-LabIsoImageDefinition -Name Office2013 -Path $labSources\ISOs\en_office_professional_plus_2013_x86_x64_dvd_1135709.iso

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'hsdlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.60.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}


Add-LabMachineDefinition -Name HSD-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.60.10'
#Add a host that will run all the roles.  Since we want to demonstrate both published desktops and apps, install Office
Add-LabMachineDefinition -Name HSD-HSD1 -Memory 4GB -IPAddress '192.168.60.20' -Roles Office2013

#Do the installation
Install-Lab

#Save a snapshot of the machines during development, remove for production deployments
Checkpoint-LABVM -All -SnapshotName 'After Build'

Invoke-LabCommand -ActivityName 'Configure Remote Desktop Services' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    New-RDSessionDeployment -ConnectionBroker 'HSD-HSD1.hsdlab.local' -WebAccessServer 'HSD-HSD1.hsdlab.local' -SessionHost 'HSD-HSD1.hsdlab.local'  
}

Restart-LabVM -ComputerName 'HSD-HSD1' -Wait

Invoke-LabCommand -ActivityName 'Configure RDS' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    Import-Module ActiveDirectory
    Add-RDServer -Server 'HSD-DC01.hsdlab.local' -Role RDS-LICENSING -ConnectionBroker 'HSD-HSD1.hsdlab.local'
    Set-RDLicenseConfiguration -LicenseServer 'HSD-DC01.hsdlab.local' -Mode PerUser -ConnectionBroker 'HSD-HSD1.hsdlab.local' -Force
    #Need to add the License server to the 'Terminal Server License Servers' group in AD
    Add-ADGroupMember 'Terminal Server License Servers' 'HSD-DC01$'
    New-RDSessionCollection –CollectionName 'SessionCollection' –SessionHost 'HSD-HSD1.hsdlab.local' –CollectionDescription 'Desktop Session Collection' –ConnectionBroker 'HSD-HSD1.hsdlab.local'  

    New-RDRemoteapp -Alias Wordpad -DisplayName WordPad -FilePath "C:\Program Files\Windows NT\Accessories\wordpad.exe" -ShowInWebAccess 1 -CollectionName 'SessionCollection' -ConnectionBroker 'HSD-HSD1.hsdlab.local'  
    
}
  
Checkpoint-LABVM -All -SnapshotName 'After RDS Install'
      
Show-LabDeploymentSummary -Detailed

