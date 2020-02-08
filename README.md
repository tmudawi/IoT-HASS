Tool Description:
===

This tool  is used to find files that are recently created or modified in the user's machine plus getting a list of users currently 
logged in the system and the time they logged in.



Technical Specification:
===

* Windows 10 Operating System.
* Python 2.7
* No other dependencies or third-party library needed.



Version 2 New Features:
===

This version include the following features:
* List all users currently logged in to the system with the initial time they logged in. The user can use this
   information to figure out who possibly created or modified the files under investigation.
* Another feature added to this version is to create an MD5 hash for each file in the directory. The user can compare
   MD5 between each run and determine which file contents changed.



Version 2 Enhancements:
===

* Path Validation: If the path to the directory that contains the files to be investigated does not exist the user is prompted to enter a valid path.
   In case the user chooses to save the results in a file, that file path is validated as well.
* File Extension Validation: The extension of the file to save the results is validated to be a .txt extension.
* Dynamic Script: All hardcoding are removed from old version, user is now prompted to enter values for path and filenames.        
* Usage Message: If the user enters a bad or missing argument when running the script a print of the correct usage will be displayed in the screen.      



Usage:
===
As illustrated below, the user simply needs to specify the script name, the path to directory where new or
modified files need to be checked, the time span in minutes and finally the flag that tell the script whether 
to print the results to the screen (P) or save them to a file (S).

Below is a sample run that print a list of files that are created within the last 30 minutes to the screen.

C:\Python27>python LocateNewFiles.py C:\PathToDirectory 30 P

If no files printed to the screen then all the files in that directory might be created/modified
before the last 30 minutes. The user can then choose to either increase the time span or stop investigating
if he is satisfied with the results.

 

