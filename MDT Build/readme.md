This script is designed to deploy Microsoft Deployment Toolkit (MDT) to an Automated-Lab provisioned server and result in a fully functional MDT+WDS server to deploy images

Prerequisites:

- Installed verison of Automated-Lab (Tested on v4.5.0)
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    (Tested with 1709 Version)
- A Server operating system image for an AL machine deployment:
    Tested on Windows Server 2012 R2, and Windows Server 2016

All other necessary files such as MDT are downloaded through the script.

Note: Script assumes internet access is avaiable to download binary files.  If no Internet access is available, at a minimum download the MDT installation files and place in the LabSources\SoftwarePackages folder, available at: https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi

Known Limitations:
- Deployed Server must be standalone. Script has not been tested deploying MDT on Domain Controllers or member servers
- Script assumes that MDT+ADK, WDS and DHCP all reside on the same server. Splitting DHCP server role in particular has not been tested.

This script is a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, designated by "Feature Enhancement" in the comment header of each function (these will be moved to an overall feature enhacements request process as traditional with Gitub)
