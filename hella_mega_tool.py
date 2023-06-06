#!/usr/bin/python3 
# hella_mega_tool.py - Is a tool that adds some of the most used pentesting
# tools in to one place. These tools are more or less based on industry 
# standard tools like nmap, dirb, hashcat and such.
# this tool is aimed at begginer pentesters, as it wont handle more
# sophisticated tasks that a seasoned pentester might require.

import time
import platform
import os
import hashlib
import ipaddress
import requests
from socket import *
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

def main_menu():
    """main_menu is the main menu of the toolkit

    Here the user has a choice between the different tools
    or to just simply quit the program
    
    """
    print(colored(("#" * 62), "green"))
    print(colored(("Choose one of the options and enter the number in the terminal\n\n\
          1. Hash Cracker\n\
          2. Net Mapper\n\
          3. Port Scanner\n\
          4. Directory Buster\n\
          5. Login Cracker\n\
          0. To Exit"), "green"))
    print(colored(("#" * 62), "green"))

    # Handling user choice input to only be what is allowed
    # and handling some errors. Takes users to the different
    # functions.
    try:
        main_choice = int(input(colored(("... "), "green")))
        if main_choice == 1:
            hash_cracker()
        elif main_choice == 2:
            network_main()
        elif main_choice == 3:
            ip_main()
        elif main_choice == 4:
            directory_buster()
        elif main_choice == 5:
            login_cracker()
        elif main_choice == 0:
            exit()
        else:
            print(colored(("Please choose one of the options !!"), "red"))
            time.sleep(2)
            main_menu()
    except ValueError as err:
        print(colored((f"Error has occured: {err}"), "red"))
        time.sleep(2)
        main_menu()
    except KeyboardInterrupt as err:
        print(colored((f"Quiting......"), "red"))
    
def hash_cracker():
    """hash_cracker tries to crack user given hashes:

        hashCrack = specify hash to crack
        wordlist = specify wordlist
        alg = specify which algorithm to use

        Then the function attempts to crack user given hash value
        with hashlib algorithms

    """
    # Takes the hash from the user or hash file
    hashCrack = input(colored(("Enter the hash you want to crack (for files use .txt): "), "green"))
    
    # Takes the wordlist from the user
    wordlist = input(colored(("Enter the full path of the wordlist: "), "green"))

    # Prints out the supported hash algorithms
    print(colored((f"These are suported\n{hashlib.algorithms_guaranteed}"), "yellow"))
    
    # User inputs the algorithm
    alg = input(colored(("Specify which type of algorithm to use: "), "green"))

    # Some user/error handling
    if wordlist == "":
        print(colored(("You need to provide a wordlist!"), "red"))
        time.sleep(2)
        hash_cracker()
    elif ".txt" not in wordlist:
        print(colored(("Please provide a .txt file for the wordlist!"), "red"))
        time.sleep(2)
        hash_cracker()
    elif hashCrack == "":
        print(colored(("Please provide a value to crack!"), "red"))
        time.sleep(2)
        hash_cracker()
    elif alg not in hashlib.algorithms_guaranteed:
        print(colored(("Please Provide a valid algorithm"), "red"))
        time.sleep(2)
        hash_cracker()
    
    # Decides what to do based on what the input endswith
    elif hashCrack.endswith(".txt"):
        try:
            with open(wordlist, mode="r") as wordfile:
               listword = wordfile.readlines()
            with open(hashCrack, mode="r") as hashfile:
                hashfile.readlines()
                hashfile.seek(0, 0)
                cracked = ""            # Empty string to append the cracked hashes to
                for hash in hashfile:
                    for word in listword:
                        h = hashlib.new(alg)
                        h.update(word.strip().encode("utf-8"))
                        if h.hexdigest() == hash.strip(): 
                            cracked = cracked + f"{word}"
            
            print(colored((f"These are the results:\n{cracked}"), "yellow"))  
            
            # Provides the opportunity for the user to save output to a file
            save = str(input(colored(("Do you want to save the results to a file? (Y/N): "), "green"))).lower()

            # Accepts only y or n and handles value errors
            try:
                if save == "y":
                    file_name = input(colored(("Enter the name of the file(No FileExtensions needed): "), "green")) + ".txt"
                    saving(file_name, cracked)

                elif save == "n":
                    print(colored(("Heading back to main menu"), "green"))
                    time.sleep(1)
                    main_menu()
                
                else:
                    print(colored(("Choose one of the options next time... Saving as default.txt..."), "red"))
                    file_name = "Default.txt"
                    saving(file_name, cracked)

            except ValueError as err:
                print(colored((f"Error has occurred: {err}"), "red"))
                time.sleep(2)
                hash_cracker()        

        except FileNotFoundError as err:
            print(colored((f"Error has occured: {err}"), "red"))
            time.sleep(2)
            hash_cracker()
    
    # Here is the other option if the user decides not to use a hash file
    else:
        try:
            with open(wordlist, mode="r") as file:
                for entry in file.readlines():
                    h = hashlib.new(alg)
                    one_cracked = ""
                    h.update(entry.strip().encode("utf-8"))
                    if h.hexdigest() == hashCrack:
                        one_cracked = one_cracked + entry.strip()
                        print(colored((f"Hash found: {entry.strip()}"), "yellow"))
                        
                        # Gives user the option to save value to a file
                        save = str(input(colored(("Do you want to save the results to a file? (Y/N): "), "green"))).lower()

                        try:
                            if save == "y":
                                file_name = input(colored(("Enter the name of the file(No FileExtensions needed): "), "green")) + ".txt"
                                saving(file_name, one_cracked)

                            elif save == "n":
                                print(colored(("Heading back to main menu"), "green"))
                                time.sleep(1)
                                main_menu()
                            
                            else:
                                print(colored(("Choose one of the options next time... Saving as default.txt..."), "red"))
                                file_name = "Default.txt"
                                saving(file_name, one_cracked)

                        except ValueError as err:
                            print(colored((f"Error has occurred: {err}"), "red"))
                            time.sleep(2)
                            hash_cracker()        
                        break

                    else:
                        pass
                
                # Incase hash could not be cracked user will be redirected back to the menu
                if h.hexdigest() != hashCrack:  
                    print(colored(("Could not crack the hash...."), "red"))
                    print(colored(("Heading back to hash menu...."), "green"))
                    time.sleep(2)
                    hash_cracker()
        
        except FileNotFoundError as err:
            print(colored((f"Error has occured: {err}"), "red"))
            time.sleep(2)
            hash_cracker()

def ip_main():
    """ip_main takes an ip address from user

    Then it targets the ip_scanner via threadpool
    which will proceed with the further scan

    """
    # IP address of the target
    address = input(colored(("Enter an IP address to be scanned: "), "green"))
    
    # Handling value errors of the port input
    try:
        port = int(input(colored(("Enter how many ports to scan: "), "green")))
    except ValueError as err:
        print(colored((f"Error has occurred: {err}"), "red"))
        time.sleep(2)
        ip_main()
    
    print(colored(("Scanning host...."), "green"))

    # Handles some user errors
    if address == "":
        print(colored(("Enter an IP address .."), "red"))
        time.sleep(2)
        ip_main()
    elif port == "":
        print(colored(("Enter a ports to scan .."), "red"))
        time.sleep(2)
        ip_main()
    elif port > 65535:
        print(colored(("Enter a valid port range .."), "red"))
        time.sleep(2)
        ip_main()

    elif ipaddress.ip_address(address):
        with ThreadPoolExecutor(max_workers=100) as pool:
            for p in range(port):
                pool.submit(ip_scanner, address, p)
        print(colored(("Scan Completed"), "green"))
        time.sleep(2)
        main_menu()          
    
def ip_scanner(address, ports):
    """ip_scanner checks for open ports
    
    Makes a connection and then based on the error msg
    will return if a port is open. Gets the parameters
    from ip_main

    """

    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(0.2)     # Wont get stuck on unresponsive ports
    
    connection = sock.connect_ex((address, ports))

    # Based on the error code decides whether the ports is open
    if connection == 0:
        print(colored((f"Port {ports} is OPEN"), "yellow"))    
    sock.close()

def net_scanner(network):
    """net_scanner uses ping to check hosts that are up

    Uses a simple ping command based on windows or 
    linux to check if the hosts are responding. Gets
    the network parameter from network_main
    """

    # Sends simple ping commands base on windows or linux
    # to determine live hosts
    system = platform.system()
    if system == "Windows":        
        win_response = os.system(f"ping -n 3 -w 3 {network} > nul")
        if win_response == 0:
            print(colored((f"{network} is Up"), "yellow"))
        else:
            pass
    else:
        lin_response = os.system(f"ping -c 3 -w 3 {network} > /dev/null")
        if lin_response == 0:
            print(colored((f"{network} is Up"), "yellow"))
        else:
            pass

def network_main():
    """network_main takes a network range from user

    Takes in a network range as input and then using
    thread pool targets net_scanner for further execution
    """
    # Gets an IP range from the user
    conn = input(colored(("Type in a network range ie.(169.69.169.0/24): "), "green"))

    # Makes the IP range
    networks = ipaddress.ip_network(conn)

    with ThreadPoolExecutor(max_workers=100) as pool:
        for net in networks:
            pool.submit(net_scanner, (net))
    print(colored(("Scan Completed.."), "green"))
    time.sleep(2)
    main_menu()

def directory_buster():
    """directory_buster enumerates directories

    directory_buster takes a url from the user in the form of
    http://example.com and a path to the wordlist. Then using
    the requests lib prints out results based on status codes
    
    """
    # The whole function is under try/except statments to handle errors
    try:  
        url = input(colored(("Enter the url of the target (ex: http://example.com): "), "green"))
        wordlist = input(colored(("Enter the path of the wordlist: "), "green"))

        # Some user error handling
        if url == "":
            print(colored(("Please provide a host to scan..."), "red"))
            directory_buster()
        elif wordlist == "":
            print(colored(("Please provide a wordlist..."), "red"))
            directory_buster()
        elif ".txt" not in wordlist:
            print(colored(("For a wordlist use txt files..."), "red"))
            directory_buster()
        else: 
            wordlist.endswith(".txt")
            
            # Handles filenotfound error/opens the file to use as a wordlist
            try:
                results = ""
                with open(wordlist, mode="rb") as wordfile:
                    for word in wordfile.readlines():
                        word = word.strip().decode("utf-8")
                        full_url = f"{url}/{word}"
                        request = requests.get(full_url)
                        if request.status_code == 200:
                            result = f"- Found {url}/{word} (Status Code:{request.status_code})"
                            print(colored((result), "yellow"))
                            results += result + "\n"
                wordfile.close()
                
                save = input(colored(("Scan Done... Save the results? (Y or N): "), "green")).lower()
                
                if save == "n":
                    directory_buster()
                elif save == "y":
                    file_name = input(colored(("Enter the filename: "), "green")) + ".txt"
                    saving(file_name, results)
                else:
                    print(colored(("Choose one of the options next time... Saving as default.txt..."), "red"))
                    file_name = "Default"
                    saving(file_name, results)

            except FileNotFoundError as err:
                print(colored((f"Error has occurred: {err}"), "red"))
                directory_buster()          

    except requests.exceptions.ConnectionError as err:
        print(colored((f"Error has occurred: {err}"), "red"))
        directory_buster()
    except requests.exceptions.MissingSchema as err:
        print(colored((f"Error has occurred: {err}"), "red"))
        directory_buster()

def login_cracker():
    """login_cracker brute forces web page authentication

    Takes the full url from user input, a txt file containing
    usernames or a single user name, takes a txt password file 
    and finally a failed login message. If successfull it returns 
    the user and password.
    
    """
    # Takes the url
    url = input(colored(("Enter the target url: "), "green"))
    # Takes the username or userfile
    user = input(colored(("Enter the username to try: "), "green"))
    # Takes the password file
    passw = input(colored(("Enter the password file(txt): "), "green"))
    # Takes the fail message from the user
    fail = input(colored(("Enter the failed login message: "), "green"))
    
    # Some user error handling
    if url == "":
        print(colored(("Enter a URL to scan .."), "red"))
        login_cracker()
    elif fail == "":
        print(colored(("Enter the error message .."), "red"))
    else:
        try:
            if user.endswith(".txt"):
                with open(user, mode="r") as user_file:
                    for user_entry in user_file:
                        user_entry = user_entry.strip()
                        if not user_entry:
                            continue
                        with open(passw, mode="r") as pass_file:
                            for pass_entry in pass_file:
                                pass_entry = pass_entry.strip()
                                if not pass_entry:
                                    continue
                                data = {"username": user_entry, "password": pass_entry, "Login":"submit"}   # This can be found via inspect element
                                request = requests.post(url, data=data)
                                print(colored((f"Trying username: {user_entry}/ Password: {pass_entry}"), "blue"))
                                if fail in request.content.decode():
                                    continue
                                else:
                                    print(colored((f"* Found Username: {user_entry} With password: {pass_entry}"), "yellow"))
                                    break
                            else:
                                continue
                            break
            else:
                with open(passw, mode="r") as file:
                    for entry in file:
                        entry = entry.strip()
                        data = {"username": user, "password": entry, "Login":"submit"}
                        request = requests.post(url, data=data)
                        print(colored((f"- Trying password: {entry}"), "blue"))
                        if fail in request.content.decode():
                            continue
                        else:
                            print(colored((f"* Found Password: {entry} for the username: {user}"), "yellow"))
                            break

        except FileNotFoundError as err:
            print(colored((f"Error has occurred: {err}"), "red"))
            time.sleep(2)
            login_cracker()
        except requests.exceptions.MissingSchema as err:
            print(colored((f"Error has occured: {err}"), "red"))
            time.sleep(2)
            login_cracker()
        except requests.exceptions.ConnectionError as err:
            print(colored((f"Error has occured: {err}"), "red"))
            time.sleep(2)
            login_cracker()

def saving(file_name, to_save):
    """saving saves results to a file

    This function functions as a save button
    saving results where needed.
    
    """
    try:    
        with open(file_name, mode="a") as f:
            f.write(to_save)
            f.close()
            print(colored(("File saved to the directory where the script is running from!"), "yellow"))
            time.sleep(2)
            main_menu()

    except PermissionError as err:
        print(colored((f"Error has occurred: {err}"), "red"))
        time.sleep(2)
        exit()
    except TypeError as err:
        print(colored((f"Error has occurred: {err}"), "red"))
        time.sleep(2)
        exit()

main_menu()
