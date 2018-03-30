These scripts are designed to deploy a Microsoft Identity Manager (MIM) Lab using AutomatedLab

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- A Server operating system image for an AL machine deployment (Tested with Server 2016)

Intent of these scripts is to deploy the following roles:

- Windows Domain Controller
- Microsoft Identity Manager 2016
- SharePoint 2016 (to Support MIM)

These scripts are a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub.

Current Scripts:

- **MIMLab.psm1** - Main Script

- **UserRights.ps1** - Script by Tony Pombo to perform assignments of rights to accounts, provides the same capabilities as available via the Local GP Editor (needed to assign specific rights to MIM + SharePoint Service accounts)

Notes:
