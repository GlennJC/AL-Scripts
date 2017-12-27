<#
.SYNOPSIS
    This module contains the Remote Desktop Services Fucntions to Install a funtioning RDS Lab in concert with AutomatedLab
.DESCRIPTION
    Author: Glenn Corbett (@GlennJC)
    Version 1.0.20171226.1938
.NOTES
    This is the initial version.
    TODO:
        Additional Error checking for all calls
        Additional Range Checking for passed in values
        Additional Error Checking for file existence for Install-RDSApplication
#>

Function Install-RDS {

    [cmdletbinding(DefaultParameterSetName='HSDDeployment')]

    param (
       
        # Parameter help description
        [Parameter(Mandatory)]
        [AutomatedLab.Machine]$ConnectionBroker,

        [Parameter(Mandatory)]
        [AutomatedLab.Machine]$WebAccessServer,

        [Parameter(Mandatory)]
        [AutomatedLab.Machine]$LicensingServer,

        [string]$CollectionName='Pool',

        [Parameter(ParameterSetName='HSDDeployment')]
        [switch]$SessionDeployment,

        [Parameter(Mandatory, ParameterSetName='HSDDeployment')]
        [AutomatedLab.Machine[]]$SessionHost,

        [Parameter(ParameterSetName='VDIDeployment')]
        [switch]$VDIDeployment,

        #Name of the host server that will host the VDI images
        [Parameter(Mandatory, ParameterSetName='VDIDeployment')]
        [string]$VirtualizationHost,

        [Parameter(Mandatory, ParameterSetName='VDIDeployment')]
        [string]$VDITemplateName,

        #Limit the number of VDI Instances between 1 and 20
        [ValidateRange(1,20)]
        [Parameter(ParameterSetName='VDIDeployment')]
        [int]$MaxInstances=1
    )

    #RDS Needs FQDNs to access lab resources from the host.
    #Add fully qualified host names to the hosts file (otherwise apps launched via RemoteApp from the host will fail since it launches using the FQDN for the Remote Desktop Client Session)
    #NOTE: This issue has been fixed in AutomatedLab.psm1 as at 23/12/17 (#206), can be removed once committed in next public release of AL.
    $machines = Get-LabMachine
    $hostFileAddedEntries = 0
    $labname = (Get-Lab).Name

    #Modified code from AutomatedLab.psm1 to add host entries, modified to add FQDN names (otherwise apps launched via RemoteApp from the host will fail)
    #entries are added to the existing section created by AL, so will be removed when the Remove-Lab command is executed.
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

    #Find the Root Domain Controller role, we will use this to execute the commands against the RDConnection Broker Server. We are unable to perform a number of commands directly on the Connection Broker
    # itself (such as the initial install) as the connection broker is restarted during installation
    $RootDC = Get-LabMachine -Role RootDC

    switch ($PSCmdlet.ParameterSetName) {
        'HSDDeployment' {

            #We need to use FQDN host names for RD activities, so make up an FQDN collection for the passed in session host(s)
            $SessionHostGroup = @()
            foreach ($SingleHost in $SessionHost) {
                $SessionHostGroup += $SingleHost.FQDN
            }

            Invoke-LabCommand -ActivityName 'Install Remote Desktop Services in HSD Deployment Mode' -ComputerName $RootDC -ScriptBlock {

                param(
                    [Parameter(Mandatory)]
                    [string]$ConnectionBrokerFQDN,
                
                    [Parameter(Mandatory)]
                    [string]$WebAccessServerFQDN,
                
                    [Parameter(Mandatory)]
                    [string[]]$SessionHostFQDN
               )
        
                Import-Module RemoteDesktop
                New-RDSessionDeployment -ConnectionBroker $ConnectionBrokerFQDN -WebAccessServer $WebAccessServerFQDN -SessionHost $SessionHostFQDN

            } -ArgumentList $ConnectionBroker.FQDN, $WebAccessServer.FQDN, $SessionHostGroup

            #Wait for the Connection Broker Service to become available, as New-RDSessionDeployment does a machine restart during the activity
            Write-ScreenInfo -Message "Waiting for Connection Broker on '$ConnectionBroker' to become available " -NoNewline

            $totalretries = 20
            $retries=0

            do {
                    $result = Invoke-LabCommand -ComputerName $RootDC -ScriptBlock { 

                    param(
                        [Parameter(Mandatory)]
                        [string]$ConnectionBrokerFQDN
                    )

                    Get-RDServer -ConnectionBroker $ConnectionBrokerFQDN -ErrorAction SilentlyContinue
                    } -ArgumentList $ConnectionBroker.FQDN -PassThru -NoDisplay

                $retries++
                Write-ScreenInfo '.' -NoNewLine
                Start-Sleep -Seconds 15

            } until (($result) -or ($retries -ge $totalretries))

            Write-ScreenInfo 'Done' 

            Invoke-LabCommand -ActivityName 'Configure Remote Desktop Services' -ComputerName $RootDC -ScriptBlock {

                param(
                    [Parameter(Mandatory)]
                    [string]$ConnectionBrokerFQDN,
                       
                    [Parameter(Mandatory)]
                    [string]$LicensingServerFQDN,
        
                    [Parameter(Mandatory)]
                    [string[]]$SessionHostFQDN,

                    [Parameter(Mandatory)]
                    [string]$CollectionName
               )
        
                Import-Module RemoteDesktop
                Import-Module ActiveDirectory 
            
                Add-RDServer -Server $LicensingServerFQDN -Role RDS-LICENSING -ConnectionBroker $ConnectionBrokerFQDN 
                Set-RDLicenseConfiguration -LicenseServer $LicensingServerFQDN -Mode PerUser -ConnectionBroker $ConnectionBrokerFQDN -Force
                #Need to add the License server to the 'Terminal Server License Servers' group in AD, we need to use the non-fqdn version of the name
                $LicensingServerHostName= $(Get-ADComputer -LDAPFilter "(dNSHostName=$LicensingServerFQDN)").Name
        
                if ($LicensingServerHostName) {
                    Add-ADGroupMember 'Terminal Server License Servers' "$LicensingServerHostName`$"
                }
                else {
                    Write-Error "Error locating dnsHostName for '$LicensingServerFQDN', server will need to be manually added to 'Terminal Server License Servers' group"
                }
                
                #create a new session collection, using the passed in single or multiple session hosts
                New-RDSessionCollection -CollectionName $CollectionName -SessionHost $SessionHostFQDN -ConnectionBroker $ConnectionBrokerFQDN -PooledUnmanaged   

            } -ArgumentList $ConnectionBroker.FQDN, $LicensingServer.FQDN, $SessionHostGroup, $CollectionName

        } #switch HSDDeployment

        'VDIDeployment' {
                Write-ScreenInfo 'VDI Deployment Scenario Not Implemented Yet'
        } #switch VDI Deployment

    }

}

function Install-RDSApplication {

    param (
       
        #Session hosts to install the application on
        [Parameter(Mandatory)]
        [AutomatedLab.Machine[]]$SessionHost,

        #URL for the application to be downloaded
        [Parameter(ParameterSetName='ByURL')]
        [string]$URL,

        #ISO Path for the installation ISO
        [Parameter(ParameterSetName='ByISO')]
        [string]$ISOPath,

        #Folder where existing installation files are located
        [Parameter(ParameterSetName='ByPath')]
        [string]$DirectoryPath,

        #Path relative to source media where installation executable is located. If a URL was provided, it is assumed the InstallExecutable is the last segment in the URL name
        [parameter(Mandatory, ParameterSetName='ByISO')]
        [parameter(Mandatory, ParameterSetName='ByPath')]
        [ValidateNotNullOrEmpty()]
        [string]$InstallExecutable,

        #Required arguments for the installation
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$InstallArguments
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ByURL' {
            #We were passed a URL of the application to install, download if necessary
            $downloadTargetFolder = Join-Path -Path $labSources -ChildPath SoftwarePackages
            $internalUri = New-Object System.Uri($URL)
            Get-LabInternetFile -Uri $internalUri -Path $downloadTargetFolder -ErrorAction Stop 
            $DownloadedFileName = $internalUri.Segments[$internalUri.Segments.Count-1]
            Write-ScreenInfo 'Copying source files to Target Servers' -TaskStart
            Copy-LabFileItem -Path (Join-Path -Path $downloadTargetFolder -ChildPath $DownloadedFileName) -DestinationFolderPath C:\Install -ComputerName $SessionHost
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $SessionHost -LocalPath "C:\Install\$DownloadedFileName" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
        }
        'ByPath' {
            Write-ScreenInfo 'Copying source directories to Target Servers' -TaskStart
            Copy-LabFileItem -Path $DirectoryPath -DestinationFolderPath 'C:\Install' -ComputerName $SessionHost -Recurse 
            Write-ScreenInfo 'Finished Copying Files' -TaskEnd
            $job = Install-LabSoftwarePackage -ComputerName $SessionHost -LocalPath "C:\Install\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
        }
        'ByISO' {
            Write-ScreenInfo 'Mounting ISO on target servers' -TaskStart
            $disk = Mount-LabIsoImage -ComputerName $SessionHost -IsoPath $ISOPath -PassThru -SupressOutput
            Write-ScreenInfo 'Finished' -TaskEnd

            $job = Install-LabSoftwarePackage -ComputerName $SessionHost -LocalPath "$($disk.DriveLetter)\$InstallExecutable" -CommandLine $InstallArguments -AsJob -PassThru -ErrorAction Stop 
            $result = Wait-LWLabJob -Job $job -NoNewLine -ProgressIndicator 10 -PassThru -ErrorAction Stop
            Dismount-LabIsoImage -ComputerName $SessionHost -SupressOutput
    
        }
    }
    
}

function Publish-RDSApplication  {

    param (
       
        [Parameter(Mandatory)]
        [AutomatedLab.Machine]$ConnectionBroker,

        [string]$CollectionName='Pool',
        
        [Parameter(Mandatory)]
        [string]$Alias,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string]$FilePath
    )
    

    Invoke-LabCommand -ActivityName "Publish '$Alias' to Collection '$CollectionName'" -ComputerName $ConnectionBroker -ScriptBlock {
        param (
       
            [Parameter(Mandatory)]
            [string]$ConnectionBroker,
    
            [Parameter(Mandatory)]
            [string]$CollectionName,
            
            [Parameter(Mandatory)]
            [string]$Alias,
    
            [Parameter(Mandatory)]
            [string]$DisplayName,
    
            [Parameter(Mandatory)]
            [string]$FilePath
        )

        New-RDRemoteapp -Alias $Alias -DisplayName $DisplayName -FilePath $FilePath -ShowInWebAccess 1 -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker 

    } -ArgumentList $ConnectionBroker.FQDN, $CollectionName, $Alias, $DisplayName, $FilePath
    
}

function Publish-RDSDesktop {

    param (
       
        [Parameter(Mandatory)]
        [AutomatedLab.Machine]$ConnectionBroker,

        [string]$CollectionName='Pool'
    )

    #This will run on each of the session hosts and re-enable the Full Desktop RemoteApp
    Invoke-LabCommand -ActivityName 'Republish Full Desktop' -ComputerName $ConnectionBroker -ScriptBlock {

        param(
            [Parameter(Mandatory)]
            [string]$CollectionName
       )

       #Registry Keys for Collections are based on the first 16 characters of the Collection Name
       If ($CollectionName.Length -gt 16) {
            $RegistryCollName = $CollectionName.Substring(0,16)
       }
       else {
            $RegistryCollName = $CollectionName
       }

       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\PublishedFarms\$RegistryCollName\RemoteDesktops\$RegistryCollName" -Name 'Name' -Value 'Full Desktop' 
       Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\PublishedFarms\$RegistryCollName\RemoteDesktops\$RegistryCollName" -Name 'ShowInPortal' -Value 1 

    } -ArgumentList $CollectionName

}

Export-ModuleMember -Function Install-RDS
Export-ModuleMember -Function Install-RDSApplication
Export-ModuleMember -Function Publish-RDSApplication
Export-ModuleMember -Function Publish-RDSDesktop
