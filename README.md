# hash_it_out.py

How can you be sure that files you've downloaded are what they're supposed to be? Check the hash!

Don't have a hash? Extra cautious? Check for known malicious hashes!  

### Hash It Out!  
  
*** **Disclaimer** ***: This script *is not*, nor is it intended to be, a malware/virus scanner, nor is it intended to replace good security practices. 
The user assumes all liability from execution/opening/modification/etc of files. 
Additionally, the list of known malicious hashes is <b>not</b> exhaustive, which may result in a false positive. 
The developer holds no responsibility should a file the user checks with this script be malicious.
By downloading and/or running this script, the user accepts this agreement and holds harmless the developer.


### Installation:
No install necessary, just do `pip install -r requirements.txt` from the hash-it-out directory

In order to use the VirusTotal API functionality, you **must** add your own API key to the source code or via interactive mode. The API is free for personal use and available at [virustotal.com](https://virustotal.com).

### Updates:  
*This is a work-in-progress.*

### Changelog:
Version 0.1.4:
Added ability to calculate a file hash and write that value to a log file. 
Added ability to add an API key without source code modification.

Version 0.1.3:  
Added the menu and the option to run the program without a known hash.

Version 0.1.2:  
Added greeting banner.  

Version 0.1.1:  
Added integration with Virus Total for scanning for known malware signatures.
