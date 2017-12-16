This script is designed to deploy Microsoft Deployment Toolkit (MDT) to an Automated-Lab provisioned device and result in a fully functional MDT+WDS server to deploy images

Prerequisites:

- Installed verison of Automated-Lab (Tested on v4.5.0)
- Download of the Microsoft Assessment and Deployment Kit - available here:
    https://developer.microsoft.com/en-us/windows/hardware/windows-assessment-deployment-kit
    (Tested with 1709 Version)
- A Server operating system image for an AL machine deployment:
    Tested on Windows Server 2012 R2, and Windows Server 2016

All other necessary files such as MDT are downloaded through the script.

This script is a work in progress, there are some assumptions made resulting in some lack of error checking, and additional enhancements are in the pipeline, designated by "Feature Enhancement" is the comment header of each function.

