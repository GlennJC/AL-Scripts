param(
    [string]$DeploymentFolderLocation = 'C:\DeploymentShare',

    [string]$InstallUserID = 'MdtService',
    
    [string]$InstallPassword = 'Somepass1',

    [Parameter(Mandatory)]
    [string]$ComputerName,

    [string[]]$OperatingSystems,

    [ValidateSet('True','False')]
    [string]$CreateTaskSequences = 'True',

    [string]$AdkDownloadPath = "$labSources\SoftwarePackages\ADK"
)

$script = Get-Command -Name $PSScriptRoot\DownloadAdk.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\DownloadAdk.ps1 @param

$script = Get-Command -Name $PSScriptRoot\InstallMDT.ps1
$param = Sync-Parameter -Command $script -Parameters $PSBoundParameters
& $PSScriptRoot\InstallMDT.ps1 @param