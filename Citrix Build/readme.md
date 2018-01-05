These scripts are designed to deploy a Citrix XenApp (Windows Server) + optionally XenDesktop (Windows Desktop) infrastructure using AutomatedLab, similar to the functionality offered by the automated installation provided as part of the XenDesktop ISO File

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- A Server operating system image for an AL machine deployment (Tested with Server 2016)
- A Server operating system image for an XenApp machine deployment (Tested with Server 2016)
- (Optional) Desktop Operating System for XenDesktop Deployment (Tested with Windows 10)

Initial intent of these scripts is to deploy the following roles:

- Windows Domain Controller
- Citrix StoreFront + Delivery Controller + Studio + SQL
- Static (non-MCS / PVS) Server image - using Citrix VDA
- Static (non-MCS / PVS) Desktop image - using Citrix VDA
- Utilise Citrix XenApp and XenDesktop optimization scripts to configure machines to support remote users

Future capabilities:

- Deployment of Machine Creation Services (MCS) XenApp (Server) and XenDesktop (Desktop) images
- Deployment of Provisioning Services (PVS) XenApp (Server) and XenDesktop (Desktop) images
- Integration with Citrix NetScaler Virtual Machine to provide complete end-to-end solution (requires some additional work to support non-windows machines)

These scripts are a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub.
