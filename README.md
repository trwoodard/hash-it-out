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
No install necessary, just do pip install -r requirements.txt from the hash-it-out directory

There are two test files included in the repository. These are for testing only!
One is a penetrating testing script and one is a sample txt file. The pentesting script may be flagged by your anti-virus, but as 
long as it's not being used against you, it's not malware!  

Hashes for the test files:  
testfile.txt  
-SHA256: 6041def7d1dc8b449bdac33c49c9491e09ec599159dca9ed97ed4c01670ad231  

testfile2.ps1  
-SHA256: 702de94116e6e5826b4cb7a1a5e0be1f55ee6761533119bc08994af78fd040af 



### Updates:  
*This is a work-in-progress.*

### Changelog:
Version 0.1.2:  
Added greeting banner.  

Version 0.1.1:  
Added integration with Virus Total for scanning for known malware signatures.
