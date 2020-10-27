Azure Application deploy Multi Tenant
=====================================

            

This script is based on the available scripts at github, which uses Graph API in order to automate common tasks that would otherwise need to be carried out using the graphical interface of the Azure website, which can be time consuming, particulary if you
 need to carry out the same action multiplke times on different tenant sites. 


This particular script is a modified version of Application_Get_Assign.ps1, which can be used in conjunction with Application_LOB_Add.ps1. 


 


Application_LOB_Add.ps1 by it self allows you to upload to deploy to a single tenant a previously uploaded msi file, but you need to specificy the name of the file (which would usually mean you would need to either run an additional command or search azure.


With my attach modded script you can search for your app name using a Visual basic interactive drop down box.


This script will also use secure xml files to pass user name and passwords (original prompted you to enter). 


even if you are only a single tenant user, this script can be useful to you, as the time spent open Azure can be time consuming. 


 


Deployed group is a static choice. 


 




 



 

        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
