param(
    
    [Parameter(Mandatory)]
    [string]$ComputerName,
    
    [string]$SCCMSiteCode = "CM1",

    [string]$SCCMBinariesDirectory = "$labSources\SoftwarePackages\SCCM1702",

    [string]$SCCMPreReqsDirectory = "$labSources\SoftwarePackages\SCCMPreReqs",

    [string]$AdkDownloadPath = "$labSources\SoftwarePackages\ADK"
)

$script = Get-Command -Name $PSScriptRoot\DownloadAdk.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\DownloadAdk.ps1 @param

$script = Get-Command -Name $PSScriptRoot\InstallSCCM.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\InstallSCCM.ps1 @param