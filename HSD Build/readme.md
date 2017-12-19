This script is designed to deploy a Hosted Shared Desktop (HSD) aka Server Based Computing (SBC) using a AutomatedLab, similar to the functionality offered by the Server Manager "Remote Desktop Services" wizard.

Future intent is to expand this script to support deploying Citrix XenDesktop (7.14 or better is the target) ontop of the initial AL Deployed Lab.

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- A Server operating system image for an AL machine deployment
- (Optional) Desktop Operating System for VDI Deployment

Intent of this script is to deploy the following roles:

- Windows Domain Controller (Windows Server 2012 R2 and Windows Server 2016)
- Remote Desktop Connection Broker
- Remote Desktop Web Access Portal
- Remote Desktop Session Host (HSD/SBC)
- VDI Session Host

This script is a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub