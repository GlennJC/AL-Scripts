
<#
.SYNOPSIS
    This script is desgined to deploy a VDI-based Remote Desktop Solution
.DESCRIPTION
    Windows Domain Controller, holding the RDS-LICENSING tole
    A Windows Server holding all other RDS roles
    A Nested VM acting as the virtualisation host server - BOO - See note below.
    No RDS Gateway Role in use

.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES

BAH: Windows does NOT currently support nested virtualisation for the virtualisation host portion of an RDS VDI deployment, and also does not support Windows 10
    as a virtualisation host for RDS VDI.

26/12/17 - Will revisit this script when a spare virtualisation host becomes available for testing (or nested virtualisation works for RDS).

#>

$labName = 'VDILab'
$labSources = Get-LabSourcesLocation

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath "C:\Hyper-V\Automation-Lab"
Add-LabVirtualNetworkDefinition -Name $LabName -AddressSpace 192.168.60.0/24

$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:Network' = $labName
    'Add-LabMachineDefinition:ToolsPath'= "$labSources\Tools"
    'Add-LabMachineDefinition:DnsServer1' = '192.168.60.10'
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 SERVERSTANDARD'
}


Add-LabMachineDefinition -Name VDI-DC01 -Memory 2GB -Roles RootDC -IPAddress '192.168.60.10' -DomainName 'vdilab.local'
#Add a host that will run all the roles.  Since we want to demonstrate both published desktops and apps, install Office
Add-LabMachineDefinition -Name VDI-HSD1 -Memory 4GB -IPAddress '192.168.60.20' -DomainName 'vdilab.local'
#Add a hoist for the nested virtualisation
Add-LabMachineDefinition -Name VDI-HV01 -Memory 4GB -IPAddress '192.168.60.30' -DomainName 'vdilab.local'
#Add a non-domained joined machine which will become the master image for guest virtual machines
Add-LabMachineDefinition -Name VDI-VDI-Master -Memory 2GB -IPAddress '192.168.60.100' -OperatingSystem 'Windows 10 Enterprise' -OperatingSystemVersion '10.0.14393.0'

Install-Lab

#Get the OS version of the host, we need Windows 2016 or Windows 10 to enable nested virtualisation
$hostOsVersion = [System.Version]((Get-CimInstance -ClassName Win32_OperatingSystem).Version) 

if ($hostOsVersion -lt [System.Version]'10.0') {
            Write-Verbose -Message "Host OS version is '$($hostOsVersion)' which is insufficient to run nested virtualisation, exiting"
            return
	} else {
            Write-Verbose -Message "Host OS version is '$($hostOsVersion)' which supports nested virtualisation, continuting"
            #Need to shut down the VM to enable virtualisation extensions
            Stop-LabVM -ComputerName 'VDI-HV01' -Wait
            #Enable Virtualisation Extensions on the Virtual Machine
            Set-VMProcessor -VMName 'VDI-HV01' -ExposeVirtualizationExtensions $true -EnableHostResourceProtection
            #Add a secondary NIC, which will be the one used by Guests, connected to the same lab virtual switch
            Add-VMNetworkAdapter -VMName 'VDI-HV01' -SwitchName $labName -Name 'Guest Access'
            #Enable MAC address spoofing on the guest access network adapter
            Get-VMNetworkAdapter -VMName 'VDI-HV01' -Name 'Guest Access' | Set-VMNetworkAdapter -MacAddressSpoofing On
            #Start the VM
            Start-LabVM -ComputerName 'VDI-HV01' -Wait
            #Install Hyper-V role with management tools
            Install-LabWindowsFeature -ComputerName 'VDI-HV01' -FeatureName 'Hyper-V' -IncludeAllSubFeature -IncludeManagementTools
            #Restart the VM to complete installation
            Restart-LabVM -ComputerName 'VDI-HV01' -Wait
            #Since Hyper-V install restarts the computer a second time, wait for 30 seconds for this to occur before continuing
            Start-Sleep -Seconds 30
            
            #Now Create the virtual switch the guests will use
            Invoke-LabCommand -ActivityName 'Configure Hyper-V' -ComputerName 'VDI-HV01' -ScriptBlock {
                Get-NetAdapter -Name 'Ethernet 2' | Rename-NetAdapter -NewName 'Guest Access'
                New-VMSwitch -Name 'Guest Access' -NetAdapterName 'Guest Access' -AllowManagementOS $false 
            } 
            
            #Now, prepare the VDI guest.
            <#
            Steps:
            Perform a sysprep on the machine
            Shut it Down
            Merge the differencing disk back into a master
            Copy the master disk into the Hyper-V host
            Use this image as a master inage for VDI
            #>

            Stop-LabVM -ComputerName 'VDI-VDI-MASTER' -Wait
            #Get the VHD atteched to the Desktp VM
            $DriveConfig = Get-VMHardDiskDrive -VMName 'VDI-VDI-Master' | Get-VHD
            #merge the existing parent and chiuld into a new standalone image
            Convert-VHD -Path $DriveConfig.Path -DestinationPath "$labSources\SoftwarePackages\VDI-MASTER.vhdx" -VHDType Dynamic
            Copy-LabFileItem -Path "$labSources\SoftwarePackages\VDI-MASTER.vhdx" -DestinationFolderPath 'C:\Hyper-V' -ComputerName 'VDI-HV01'

            #Test: Create a test VM and vlidate the disk copy
            # Invoke-LabCommand -ActivityName 'Create Guest Machine' -ComputerName 'VDI-HV01' -ScriptBlock {
            #     New-VM -Name Win10VM -MemoryStartupBytes 2GB -BootDevice VHD -VHDPath 'C:\Hyper-V\VDI-MASTER.VHDX' -Path 'C:\Hyper-V' -Generation 2 -Switch 'Guest Access'              
                
            # }        
            
    }
