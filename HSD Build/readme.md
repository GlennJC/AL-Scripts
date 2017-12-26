These scripts are designed to deploy a Hosted Shared Desktop (HSD) aka Server Based Computing (SBC) using AutomatedLab, similar to the functionality offered by the Server Manager "Remote Desktop Services" wizard.

Future intent is to expand these scripts to support deploying Citrix XenDesktop (7.14 or better is the target) ontop of the initial AL Deployed Lab.

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- A Server operating system image for an AL machine deployment (Tested with Server 2016)
- (Optional) Desktop Operating System for VDI Deployment - see notes below

Intent of these scripts is to deploy the following roles:

- Windows Domain Controller
- Remote Desktop Connection Broker
- Remote Desktop Web Access Portal
- Remote Desktop Session Host (HSD/SBC)
- VDI Session Host - see notes below

These scripts are a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub.

Current Scripts: 
- **InstallRDS.psm1** - Powershell module containing the developed functions for managing an RDS install in concert with AutomatedLab

- **HSDBuild - Single HSD No Apps.ps1** - Sample script to deploy a single DC + Session Host

- **HSDBuild - Single HSD Mutiple Apps.ps1** - Sample script deploying a single DC + Session Host + Installing and publishing Firefox + Office 2016

- **HSDBuild - Multiple HSD No Apps.ps1** - Sample script deploying a DC + 4 Server Session Host Lab

Note:
VDI development is currently (26.12.17) on hold due to some limitations:
- Remote Desktop Services does not currently support nested (ie Hyper-V on Hyper-V) virtualisation for VDI Virtualisation Hosts
- Remote Desktop Services does not currently support using Windows 10 for VDI Virtualisation hosts
