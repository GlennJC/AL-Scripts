
<#
.SYNOPSIS
    This script deployed a minimal RDS Desktop Deployment with One Domain Controller and a RDS Session Host Server
.DESCRIPTION
    Windows Domain Controller, holding the RDS-LICENSING tole
    A Windows Server holding all other RDS roles, as well as being a session host Server
    No RDS Gateway Role in use

.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    Example uses a Volume License Edition of Microsoft Office 2016. Click to Run and non-VL version of Office can be installed, however will throw errors
        when the app is run that this configuration is not supported
#>

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
#Add a host that will run all the roles.  Since we want to demonstrate both published desktops and apps, install Office
Add-LabMachineDefinition -Name HSD-HSD1 -Memory 4GB -IPAddress '192.168.60.20' 
#Do the installation
Install-Lab

#Add fully qualified host names to the hosts file (otherwise apps launched via RemoteApp from the host will fail since it launches using the FQDN for the Remote Desktop Client Session)
#NOTE: This issue has been fixed in AutomatedLab.psm1 as at 23/12/17 (#206), can be removes once comitted in next public release of AL.
$machines = Get-LabMachine
$hostFileAddedEntries = 0
#Modified code from AutomatedLab.psm1 to add host entries, modified to add FQDN names (otherwise apps launched via RemoteApp from the host will fail)
#enteries are added to the existing section created by AL, so will be removed when the Remove-Lab command is executed.
Foreach ($machine in $machines)
{
    if ($machine.Hosttype -eq 'HyperV' -and $machine.NetworkAdapters[0].Ipv4Address)
    {
        $hostFileAddedEntries += Add-HostEntry -HostName $machine.FQDN -IpAddress $machine.IpV4Address -Section $labname
    }
}

if ($hostFileAddedEntries)
{
    Write-ScreenInfo -Message "$hostFileAddedEntries records have been added to the hosts using machine FQDNs. Clean them up using 'Remove-Lab' or manually if needed" -Type Warning
}

#Save a snapshot of the machines during development, remove for production deployments
Checkpoint-LABVM -All -SnapshotName 'After Build'

Invoke-LabCommand -ActivityName 'Configure Remote Desktop Services' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    New-RDSessionDeployment -ConnectionBroker 'HSD-HSD1.hsdlab.local' -WebAccessServer 'HSD-HSD1.hsdlab.local' -SessionHost 'HSD-HSD1.hsdlab.local' 
}

#Wait for the Connection Broker Service to become available, as New-RDSessionDeployment does a machine restart during the activity
Write-ScreenInfo -Message "Waiting for Connection Broker on 'HSD-HSD1.hsdlab.local' to become available " -NoNewline

$totalretries = 20
$retries=0

do {
    $result = Invoke-LabCommand -ComputerName 'HSD-DC01' -ScriptBlock { 
        Get-RDServer -ConnectionBroker 'HSD-HSD1.hsdlab.local' -ErrorAction SilentlyContinue
    } -PassThru -NoDisplay
    $retries++
    Write-ScreenInfo '.' -NoNewLine
    Start-Sleep -Seconds 15
} until (($result) -or ($retries -ge $totalretries))

Write-ScreenInfo 'Done'

Invoke-LabCommand -ActivityName 'Configure RDS' -ComputerName 'HSD-DC01' -ScriptBlock {
    Import-Module RemoteDesktop
    Import-Module ActiveDirectory 
    
    Add-RDServer -Server 'HSD-DC01.hsdlab.local' -Role RDS-LICENSING -ConnectionBroker 'HSD-HSD1.hsdlab.local' 
    Set-RDLicenseConfiguration -LicenseServer 'HSD-DC01.hsdlab.local' -Mode PerUser -ConnectionBroker 'HSD-HSD1.hsdlab.local' -Force
    #Need to add the License server to the 'Terminal Server License Servers' group in AD
    Add-ADGroupMember 'Terminal Server License Servers' 'HSD-DC01$'
    New-RDSessionCollection -CollectionName 'SessionCollection' -SessionHost 'HSD-HSD1.hsdlab.local' -ConnectionBroker 'HSD-HSD1.hsdlab.local' -PooledUnmanaged   
}

Copy-LabFileItem -Path "$labSources\SoftwarePackages\Microsoft Office Pro Plus 2016" -DestinationFolderPath 'C:\Install' -ComputerName 'HSD-HSD1'-Recurse

Invoke-LabCommand -ActivityName 'Install Office and Publish Apps' -ComputerName 'HSD-HSD1' -ScriptBlock {
    #Install Office
    Start-Process -FilePath "C:\Install\Microsoft Office Pro Plus 2016\Setup.exe" -ArgumentList "/adminfile Office_R2.MSP" -Wait
    New-RDRemoteapp -Alias 'Microsoft Word' -DisplayName 'Microsoft Word' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\WINWORD.EXE" -ShowInWebAccess 1 -CollectionName 'SessionCollection' -ConnectionBroker 'HSD-HSD1.hsdlab.local'      
    New-RDRemoteapp -Alias 'Microsoft Excel' -DisplayName 'Microsoft Excel' -FilePath "C:\Program Files (x86)\Microsoft Office\Office16\EXCEL.EXE" -ShowInWebAccess 1 -CollectionName 'SessionCollection' -ConnectionBroker 'HSD-HSD1.hsdlab.local'      
}

$FireFoxURI = 'https://ftp.mozilla.org/pub/firefox/releases/57.0/win64/en-US/Firefox%20Setup%2057.0.exe'
$downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
$downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath 'Applications'
$downloadTargetFolder = Join-Path -Path $downloadTargetFolder -ChildPath 'Mozilla Firefox'
New-Item -Path "$downloadTargetFolder" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Get-LabInternetFile -Uri $FireFoxURI -Path $downloadTargetFolder -ErrorAction Stop  
$destinationFolderName = Join-Path -Path 'C:\Install' -ChildPath 'Applications'
Copy-LabFileItem -Path $downloadTargetFolder -DestinationFolderPath $destinationFolderName -ComputerName 'HSD-HSD1'-Recurse

Invoke-LabCommand -ActivityName 'Install Firefox and Publish Applications' -ComputerName 'HSD-HSD1' -ScriptBlock {
    #Install Firefox
    Start-Process -FilePath "C:\Install\Applications\Mozilla Firefox\Firefox%20Setup%2057.0.exe" -ArgumentList "-ms" -Wait
    #Add an icon for Firefox and Wordpas as examples
    Import-Module RemoteDesktop
    New-RDRemoteapp -Alias Firefox -DisplayName Firefox -FilePath "C:\Program Files\Mozilla Firefox\firefox.exe" -ShowInWebAccess 1 -CollectionName 'SessionCollection' -ConnectionBroker 'HSD-HSD1.hsdlab.local'      
    New-RDRemoteapp -Alias Wordpad -DisplayName WordPad -FilePath "C:\Program Files\Windows NT\Accessories\wordpad.exe" -ShowInWebAccess 1 -CollectionName 'SessionCollection' -ConnectionBroker 'HSD-HSD1.hsdlab.local'  
    #Re-Enable the Published Desktop
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\PublishedFarms\SessionCollectio\RemoteDesktops\SessionCollectio' -Name 'ShowInPortal' -Value 1
}

#Save a snapshot of the machines during development, remove for production deployments
Checkpoint-LABVM -All -SnapshotName 'After Lab Completion'
      
Show-LabDeploymentSummary -Detailed

