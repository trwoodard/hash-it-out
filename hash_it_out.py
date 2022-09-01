import os
import hashlib
import shutil
import platform
import getpass
import requests
import json

'''
The purpose of this script is to make checking and comparing file hashes easier
The script will take user input for a filename, and check the SHA256 hash of the file
It will then take user input of the hash to compare the file against
If the hashes match, it will return an OK message
If hashes do not match, it will move the file into a quarantine folder to help
prevent accidental running/opening of the file
It will then ask if the user wants to permanently remove the file from the computer
'''


def disclaimer():
    print("\n***DISCLAIMER***\n"
          "This script is NOT, nor is it intended to be, a malware/virus scanner, nor is it intended\n"
          "to replace good security practices. The user assumes all liability from execution/opening/\n"
          "modification/etc of files. Additionally, the database of known malware signatures is not\n"
          "exhaustive, nor does it detect Zero-Day malware. This may result in a false positive. \n"
          "Use good judgement when deciding where you get your files and whether you should run them.\n"
          "By downloading and/or running this script, the user accepts this agreement and holds\n"
          "harmless the developer. This script is currently version 0.5, and is only compatible with \n"
          "Windows and OSX hosts and SHA256 hashes.\n")


def os_check():
    op_sys = platform.system()
    # Windows
    if op_sys == 'Windows':
        os_file_path = 'C:\\Users\\' + os.getlogin() + '\\Downloads\\'
    # Linux
    elif op_sys == 'Linux':
        os_file_path = '/home/' + os.getpass.getuser() + '/'
    # MacOS
    else:
        os_file_path = '/Users/' + os.getlogin() + '/Downloads/'
    return os_file_path


# function to check the hash of a given file
def file_to_check(filename):
    default_folder = input('Is the file in your downloads folder? Y or N: ').lower()
    os_type = os_check()
    if default_folder == 'y':
        filepath = os_type + filename
    else:
        path = input('Please specify the full file path (without the file name)\n'
                     'Do not include the trailing slash: ')
        filepath = path + '\\' + filename
        while not os.path.exists(filepath):
            print('Invalid file name or path.')
            filepath = input('Please specify the full file path, including the file name: ')
    try:
        with open(filepath, 'rb') as f:
            byte_string = f.read()
            file_hash = hashlib.sha256(byte_string)
        hash_digest = file_hash.hexdigest()
        return hash_digest, filepath
    except FileNotFoundError:
        print('File not found! Double check the file name and path!')
        file_to_check(filename)


# The main hash comparison function
def comparison(hash_one, hash_two):
    print('\n ' + '=' * 84, '\n', f'True file hash:     {hash_one}', '\n',
          f'Supplied file hash: {hash_two}', '\n', '=' * 84)
    if hash_one == hash_two:
        match = True
    else:
        match = False
    return match


def api_check(api_key):
    if len(api_key) != 0:
        return True


# This will integrate with the VirusTotal API to check the file hash against the online DB
def vt_check(hash_one):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    virustotal_api = ''
    if api_check(virustotal_api):
        params = {'apikey': virustotal_api,
                  'resource': hash_one}
        response = requests.get(url, params=params)
        vt_report = response.json()
        if vt_report['response_code'] == 1:
            scanner_names = []
            positive_count = 0
            total_scan_count = vt_report['total']
            for values in vt_report['scans']:
                scanner_names.append(values)
            for item in scanner_names:
                scan_attributes = []
                sub_dict = vt_report['scans'][item]
                for key in sub_dict:
                    scan_attributes.append(key)
                if sub_dict[scan_attributes[0]]:
                    positive_count += 1
            malware_probability = int((positive_count / total_scan_count) * 100)
            if malware_probability > 0:

                print('''
            !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            !!!!!!!!!!!!!!! WARNING - MALWARE SUSPECTED !!!!!!!!!!!!!!
            !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            ''' +
                      f'\n\nVirusTotal scanned your file and {malware_probability}% of '
                      'sources determined your file to be malicious!\n'
                      '\nYour VirusTotal scan report is available at: \n' +
                      vt_report['permalink'] + '\n\n')
            else:
                print(f'\nVirusTotal scanned your file and {positive_count} sources flagged it as malicious.')
        else:

            print('Your file was not found in the Virus Total database.\n'
                  'This does not necessarily mean the file is safe.\n'
                  'Proceed with caution! Only open the file if you are sure of its source!')
    else:
        exit('API ERROR: No API Key found. Program unable to integrate with VirusTotal.\n'
             'Please modify the script code and enter your API key in the vt_check() function.\n'
             'The variable name is virustotal_api. You can still run this script,\n'
             'but it has severely limited functionality.\n')


# This will take a file, create a directory in the same path as the target file
# and quarantine the suspicious file there
def file_quarantine(filename, filepath):
    new_path = filepath.strip(filename)
    store_directory = new_path + 'QUARANTINED_FILES'
    if os.path.exists(store_directory):
        pass
    else:
        os.mkdir(store_directory)
    shutil.move(filepath, store_directory)
    print('File quarantined at ' + store_directory)
    return store_directory


# This will prompt for deletion of the quarantined file and quarantine folder
def file_be_gone(filename, store_directory):
    choice = input('\nDo you want to permanently remove this quarantined file? \n'
                   'Also deletes the quarantine folder. THIS CANNOT BE UNDONE! Y or N: ').lower()
    if choice == 'y':
        os.remove(store_directory + '\\' + filename)
        dir_to_remove = store_directory
        print('\n*Quarantined File Deleted')
        if len(os.listdir(dir_to_remove)) == 0:
            os.rmdir(store_directory)
            print('**Quarantine Folder Deleted')
        else:
            print('***Other Files Remain Quarantined')
    else:
        print('Quarantined File NOT Deleted')


# Safe to use file print statement
def okay_to_use():
    print('\n*** HASHES MATCH ***\n'
          '***CHECKING MALWARE SIGNATURES. PLEASE WAIT.***\n')


# danger do not use print statement
def danger_warn():
    print('''
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!! HASHES DO NOT MATCH! DO NOT USE FILE !!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!! QUARANTINING FILE !!!!!!!!!!!!!!!!!!!                     
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!! CHECKING VIRUS TOTAL !!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    ''')


def main():
    try:
        disclaimer()
        filename = input('Enter the file name: ')
        first_hash, filepath = file_to_check(filename)
        second_hash = input('What is the hash supposed to be? ').lower()
        hash_match = comparison(first_hash, second_hash)

        if hash_match:
            okay_to_use()
            vt_check(first_hash)
        else:
            danger_warn()
            vt_check(first_hash)
            store_directory = file_quarantine(filename, filepath)
            file_be_gone(filename, store_directory)

        another_one = input('\n\nWould you like to scan another file? Y or N: ').lower()
        if another_one == 'y':
            print('\n\n')
            main()
        else:
            print('\n\nGoodbye')
            exit()
    except KeyboardInterrupt:
        print('\n\nProgram Exiting. Goodbye.')


if __name__ == '__main__':
    main()
