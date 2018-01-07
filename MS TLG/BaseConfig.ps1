#Cleanup from last run
Remove-Item -Path 'C:\Temp\BaseConfig.log' -Force -ErrorAction SilentlyContinue
Start-Transcript -Path 'C:\Temp\BaseConfig.log'

$labName = 'BaseConfig'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "D:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name 'CORPNET' -AddressSpace 10.0.0.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DomainName' = 'corp.contoso.com'
    'Add-LabMachineDefinition:DnsServer1' = '10.0.0.1'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}



$DCrole = Get-LabMachineRoleDefinition -Role RootDC
$CARole += Get-LabMachineRoleDefinition -Role CaRoot @{ 
    CAType              = "EnterpriseRootCA"
	CACommonName        = "corp-DC1-CA"
    KeyLength           = "2048"
    ValidityPeriod      = "Weeks"
    ValidityPeriodUnits = "4"
} 


Add-LabMachineDefinition -Name DC1 -Memory 2GB -Roles $DCRole,$CARole -IPAddress '10.0.0.1' -Network 'CORPNET'
Add-LabMachineDefinition -Name APP1 -Memory 2GB -IPAddress '10.0.0.3' -Network 'CORPNET'
#Add-LabMachineDefinition -Name CLIENT1 -Memory 2GB -OperatingSystem 'Windows 7 ULTIMATE'
# Add-LabMachineDefinition -Name CLIENT1 -Memory 2GB-IPAddress '192.168.40.20'

Install-Lab -NetworkSwitches -BaseImages -VMs

#This sets up all domains / domain controllers
Install-Lab -Domains

#Install CA server(s)
Install-Lab -CA

#Configure the CRL Distribution Settings
Invoke-LabCommand -ActivityName 'Configure the CRL Distribution Settings' -ComputerName 'DC1' -ScriptBlock {
    Add-CACrlDistributionPoint -Uri 'http://crl.corp.contoso.com/crld/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl' -AddToCertificateCdp -Force
    Add-CACrlDistributionPoint -Uri '\\app1\crldist$\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl' -PublishToServer -PublishDeltaToServer -Force
    Restart-Service -Name 'CertSvc' -Force
}

#Create a DNS record for crl.corp.contoso.com
Invoke-LabCommand -ActivityName 'Create a DNS record for crl.corp.contoso.com' -ComputerName 'DC1' -ScriptBlock {
    Add-DnsServerResourceRecordA -Name "CRL" -ZoneName "corp.contoso.com" -AllowUpdateAny -IPv4Address "10.0.0.3" -TimeToLive 01:00:00
}

#Create a user account in Active Directory
Invoke-LabCommand -ActivityName 'Create a user account in Active Directory' -ComputerName 'DC1' -ScriptBlock {
    New-ADUser -Name 'User1' -SamAccountName 'User1' -UserPrincipalName 'User1@corp.contoso.com' -AccountPassword (ConvertTo-SecureString -AsPlainText 'Somepass1' -Force) -ChangePasswordAtLogon $false -PasswordNeverExpires $true -Enabled $true
    Add-ADGroupMember  'Domain Admins' -Members 'User1'
}

#Configure computer certificate auto-enrollment
Enable-LabCertificateAutoenrollment -Computer

#Configure computer account maximum password age
#TODO - Powershell Group Policy cmdlets are severely lacking in this space

#Install the Web Server (IIS) role on APP1
#Perform a default install of IIS
Install-LabWindowsFeature -ComputerName 'APP1' -FeatureName 'Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Health,Web-Http-Logging,Web-Performance,Web-Stat-Compression,Web-Security,Web-Filtering,Web-Mgmt-Tools,Web-Mgmt-Console'

#Create a web-based CRL distribution point
Invoke-LabCommand -ActivityName 'Create a web-based CRL distribution point' -ComputerName 'APP1' -ScriptBlock {
    #Create the directory to hold the CRL
    New-Item -Path 'C:\CRLDist' -ItemType Directory -Force
    #Create a Virtual Directory in IIS
    New-WebVirtualDirectory -Site "Default Web Site" -Name "CRLD" -PhysicalPath "C:\CRLDIST"
    #Enable Directory Browsing
    Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name 'enabled' -PSPath 'IIS:\Sites\Default Web Site\CRLD' -Value $true
    #enable request filtering
    Set-WebConfigurationProperty -filter /system.webServer/security/requestFiltering -name 'allowDoubleEscaping' -PSPath 'IIS:\Sites\Default Web Site\CRLD' -Value $true
    #Enable SSL
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https
    #Assign Certificate to SSL
}
