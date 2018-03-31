param(
    
    [Parameter(Mandatory)]
    [string]$ComputerName,
    
    [string]$AdkDownloadPath = "$labSources\SoftwarePackages\ADK"
)

$script = Get-Command -Name $PSScriptRoot\DownloadAdk.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\DownloadAdk.ps1 @param

$script = Get-Command -Name $PSScriptRoot\InstallSCCM.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\InstallSCCM.ps1 @param