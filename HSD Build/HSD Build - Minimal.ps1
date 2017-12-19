
$labName = 'HSDLabMinimal'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.60.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'hsdlab.local'
    'Add-LabMachineDefinition:DnsServer1' = '192.168.60.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}


Add-LabMachineDefinition -Name HSD-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.60.10'
Add-LabMachineDefinition -Name HSD-HSD1 -Memory 2GB -IPAddress '192.168.60.20'
Add-LabMachineDefinition -Name HSD-HSD2 -Memory 2GB -IPAddress '192.168.60.21'


#Do the installation
Install-Lab

#Save a snapshot of the machines during development, remove for production deployments
Checkpoint-LABVM -All -SnapshotName 'After Build'

Invoke-LabCommand -ActivityName 'Configure Remote Desktop Services' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    New-RDSessionDeployment -ConnectionBroker 'HSD-HSD1.hsdlab.local' -WebAccessServer 'HSD-HSD1.hsdlab.local' -SessionHost 'HSD-HSD1.hsdlab.local'  
}

Restart-LabVM -ComputerName 'HSD-HSD1' -Wait

Invoke-LabCommand -ActivityName 'Add RD Licensing Server' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    Add-RDServer -Server 'HSD-HSD2.hsdlab.local' -Role RDS-RD-SERVER -ConnectionBroker 'HSD-HSD1-hsdlab.local'
    Add-RDServer -Server 'HSD-DC01.hsdlab.local' -Role RDS-LICENSING -ConnectionBroker 'HSD-HSD1.hsdlab.local'
    Set-RDLicenseConfiguration -LicenseServer 'HSD-DC01.hsdlab.local' -Mode PerUser -ConnectionBroker 'HSD-HSD1.hsdlab.local' -Force
}

#Add A Session Host Collection (Full Desktop) on the first Server
Invoke-LabCommand -ActivityName 'Add Session Collection' -ComputerName 'HSD-HSD1' -ScriptBlock {
    Import-Module RemoteDesktop
    New-RDSessionCollection –CollectionName SessionCollection –SessionHost 'HSD-HSD1.hsdlab.local' –CollectionDescription 'Desktop Session Collection' –ConnectionBroker 'HSD-HSD1.hsdlab.local'  
}

#Add A RemoteApp Collection on the second Server
Invoke-LabCommand -ActivityName 'Add RemoteApp Collection' -ComputerName 'HSD-HSD2' -ScriptBlock {
    Import-Module RemoteDesktop
    New-RDSessionCollection –CollectionName RemoteAppCollection –SessionHost 'HSD-HSD2.hsdlab.local' –CollectionDescription 'RemoteApp Session Collection' –ConnectionBroker 'HSD-HSD1.hsdlab.local'
}
   
Checkpoint-LABVM -All -SnapshotName 'After RDS Install'
      
Show-LabDeploymentSummary -Detailed

