These scripts are designed to proviude an Automated-Lab approach to the Microsoft Test Lab Guides (TLG) which are used to provide examples of Microsoft Technolgies and provide a platform for detailed learning and experimentation.

The test lab guides have been superceded in a large part by the TechNet Virtual Labs, however the Technet Labs are typically time limited, and designed to showcase a particular activity (such as deploying SCCM). They are not really designed to allow for an open ended freeform approach to learning which I find much more useful than following a bouncing ball.

Microsoft Test Lab Guides homepage: https://social.technet.microsoft.com/wiki/contents/articles/1262.test-lab-guides.aspx

Prerequisites:

- Installed version of Automated-Lab (Tested on v4.5.0)
- Access to the Test Lab Guides (link above)

Initial intent of these scripts is to deploy the base Test Lab Guide configuration (https://www.microsoft.com/en-us/download/details.aspx?id=6815), which is then used by additional labs.

Additional scripts will be developed to encompass various labs as needs require.

**Note:** Due to the lack of maintenance of many labs, the base configuration lab will be updated to support more current versions of Server and Desktop Operating Systems, as well as applications (such as System Center)

Where possible, AutomatedLab processes and functions will be used for deployment activities.  Where deployment activities require developing powershell code, they will be organised as much as practical using the heading text within the Test Lab guide. This will allow individual activities to be isolated for performing manually via the GUI, or viewing the equivalent powershell code to perform the same activity as in the guide.

Current Scripts:

- **BaseConfig.ps1** - Configures the base environment for the TestLab Guides, consisting of the following:
    - DC1 - Domain Controller with Active Directory + DNS + Certificate Services + DHCP
    - APP1 - Member Server with IIS
    - CLIENT1 - Member Workstation
    - EDGE1 - Member Server acting as a router
    - INET1 - Standalone Server with IIS + DNS + DHCP
    
These scripts are a work in progress, there are some assumptions made resulting in some lack of error checking. Additional enhancements are in the pipeline, and are managed as enhancement requests within GitHub.
