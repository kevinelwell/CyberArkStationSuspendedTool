

This directory must contain all of the files within the PACLI-Rls-x.x.zip (where x.x is the version you are licensed for)



Additionally you will need to create and/or cofigure the logonfile.ini, StationSuspendedTool.ini and Vault.ini for your environment. (see below)

========================================================================================================================================================
logonfile.ini:
- create the logonfile with the account/password you want to use for this tool.
- the account you use must have the ability to unlock users within CyberArk.
========================================================================================================================================================


========================================================================================================================================================
StationSuspendedTool.ini:

CyberArk Section - [CyberArk]
PSMIP- input the PSM ip address or a secure server ip address 
NetworkArea - input the networkarea for your environment

Email Section - [Email]
SMTPServer - input the smtp server address/ip address for your environment
SMTPFrom - input the smtp from email address for your environment
SMTPTo - input the smtp to email address/addresses for your environment

Active Directory Section - [ActiveDirectory]
CyberArkADUserGroup - input the Active Directory group that grants Active Directory user accounts access to CyberArk for your environment
CyberArkADSupportGroup - input the Active Directory group that grants Active Directory user accounts access to the CyberArk Station Suspended Tool for your environment

Administrative Functions - [AdminFunctions]
SuperSecretAdminPrefix - input the string (MUST BE ALL UPPERCASE LETTERS and numbers only) that grants access to the DEACTIVATE/ACTIVE button for your environment
========================================================================================================================================================


========================================================================================================================================================
Vault.ini:
Vault- input the vault name for your environment
Address- input the vault ip address for your environment
========================================================================================================================================================

A sample StationSuspendedTool.ini has been placed in this directory for you.