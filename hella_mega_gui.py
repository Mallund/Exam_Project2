#!/usr/bin/python3 
# hella_mega_gui.py - Is a tool that adds some of the most used pentesting
# tools in to one place but now in GUI. These tools are more or less based on industry 
# standard tools like nmap, dirb, hashcat and such.
# this tool is aimed at begginer pentesters, as it wont handle more
# sophisticated tasks that a seasoned pentester might require.


import hashlib
import ipaddress
import os
import platform
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from socket import *
from tkinter import filedialog
from tkinter.messagebox import showerror, showinfo, showwarning
import customtkinter as ctk
import tkinter.messagebox


# The main menu of the script
# options that take the user to different tools
root = ctk.CTk()
root.geometry("600x450")
root.title("Hella Mega Hacking Tool")

menu_label = ctk.CTkLabel(root, font=("Helvetica", 18, "bold"), text="Hella Mega Tools")
menu_label.place(x = 215, y = 20)

network_button = ctk.CTkButton(root, text="Network Mapper", command=lambda:network_gui_menu())
network_button.place(x = 220, y = 50)

ip_button = ctk.CTkButton(root, text="Port Scanner", command=lambda:ip_gui_menu())
ip_button.place(x = 220, y = 90)

dir_button = ctk.CTkButton(root, text="Directory Buster", command=lambda:dir_gui_menu())
dir_button.place(x = 220, y = 130)

login_button = ctk.CTkButton(root, text="Login Cracker", command=lambda:login_gui_menu())
login_button.place(x = 220, y = 170)

hash_button = ctk.CTkButton(root, text="Hash Cracker", command=lambda:hash_gui_menu())
hash_button.place(x = 220, y = 210)

def network_gui_menu():
    """network_gui_menu main menu of network mapper

    Just a graphical user interface of network mapper!
    
    """
    net_gui = ctk.CTkToplevel()
    net_gui.geometry("600x450")
    net_gui.title("Network Scanner")

    net_label = ctk.CTkLabel(net_gui, font=("Helvetica", 18, "bold"), text="Enter a network range to scan(ex: 192.168.10.0/24)")
    net_label.place(x = 80, y = 50)

    conn_entry = ctk.CTkEntry(net_gui, width=200)
    conn_entry.place(x = 200, y = 80)

    net_button = ctk.CTkButton(net_gui, font=("Helvetica", 14, "bold"),text="Begin Scan", command=lambda:start_network_main(conn_entry))
    net_button.place(x = 230, y = 410)

    result_box = ctk.CTkTextbox(net_gui, width=400, height=250)
    result_box.place(x = 100, y = 150)

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
                result_box.insert("insert", f"{network} is Up\n")
            else:
                pass
        else:
            lin_response = os.system(f"ping -c 3 -w 3 {network} > /dev/null")
            if lin_response == 0:
                result_box.insert("insert", f"{network} is Up\n")
            else:
                pass

    def network_main(conn):
        """network_main takes a network range from user

        Takes in a network range as input and then using
        thread pool targets net_scanner for further execution
        """
        try:
            conn = conn_entry.get()

            networks = ipaddress.ip_network(conn)

            with ThreadPoolExecutor(max_workers=100) as pool:
                result_box.insert("insert", "Scanning starting..\n")
                for net in networks:
                    pool.submit(net_scanner, (net))
            result_box.insert("insert", "Scan completed..\n")
        
        except ValueError as err:
            showerror("Error", f"Error has occurred: {err}")

    def start_network_main(conn_entry):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=network_main, args=(conn_entry,)).start()

def ip_gui_menu():
    """ip_gui_menu main menu of port mapper

    Just a main menu of the port mapper!
    
    """
    ip_gui = ctk.CTkToplevel()
    ip_gui.geometry("600x450")
    ip_gui.title("Port Scanner")

    ip_label = ctk.CTkLabel(ip_gui, font=("Helvetica", 14, "bold"), 
                            text="Enter an IP to scan(ex: 192.168.10.13)")
    ip_label.place(x = 30, y = 50)

    port_label = ctk.CTkLabel(ip_gui, font=("Helvetica", 14, "bold"), 
                            text="How many ports you wish to scan")
    port_label.place(x = 330, y = 50)

    address_entry = ctk.CTkEntry(ip_gui, width=200)
    address_entry.place(x = 55, y = 80)

    port_entry = ctk.CTkEntry(ip_gui, width=100)
    port_entry.place(x = 390, y = 80)

    net_button = ctk.CTkButton(ip_gui, font=("Helvetica", 14, "bold"),text="Begin Scan", 
                            command=lambda:start_ip_main(port_entry))
    net_button.place(x = 230, y = 410)

    result_box = ctk.CTkTextbox(ip_gui, width=400, height=250)
    result_box.place(x = 100, y = 150)

    def ip_main(port):
        """ip_main takes an ip address from user

        Then it targets the ip_scanner via threadpool
        which will proceed with the further scan

        """
        # IP address of the target
        address = address_entry.get()
        
        # Handling value errors of the port input
        try:
            port = int(port_entry.get())
        except ValueError as err:
            showerror("Error", f"Error has occurred: {err}")

        # Handles some user errors
        if address == "":
            showwarning("Warning", "Enter an IP address ..")
            ip_main()
        elif port == "":
            showwarning("Warning", "Enter a ports to scan ..")
        elif port > 65535:
            showwarning("Warning", "Enter a valid port range ..")
        try:    
            if ipaddress.ip_address(address):
                with ThreadPoolExecutor(max_workers=100) as pool:
                    result_box.insert("insert", "Scan starting..\n")
                    for p in range(int(port)):
                        pool.submit(ip_scanner, address, p)
                result_box.insert("insert", "Scan Completed\n")
        except ValueError as err:
            showerror("Error", f"Error has occurred: {err}")
            
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
            result_box.insert("insert", f"Port {ports} is OPEN\n")  
        sock.close()

    def start_ip_main(port_entry):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=ip_main, args=(port_entry,)).start()

def dir_gui_menu():
    """dir_gui_menu gui of directory scanner
    
    """
    dir_gui = ctk.CTkToplevel()
    dir_gui.geometry("600x450")
    dir_gui.title("Directory scanner")

    url_label = ctk.CTkLabel(dir_gui, font=("Helvetica", 14, "bold"), 
                            text="Enter an address to scan(ex: http://example.com)")
    url_label.place(x = 30, y = 50)

    url_entry = ctk.CTkEntry(dir_gui, width=200)
    url_entry.place(x = 30, y = 80)

    wrd_label = ctk.CTkLabel(dir_gui, font=("Helvetica", 14, "bold"), 
                            text="Choose Wordlist")
    wrd_label.place(x = 30, y = 120)   

    open_file_button = ctk.CTkButton(dir_gui, text="Select a wordlist", command=lambda:open_file())
    open_file_button.place(x = 25, y = 150)

    result_text_box = ctk.CTkTextbox(dir_gui, width=400, height=200)
    result_text_box.place(x = 100, y = 200)

    dir_main_button = ctk.CTkButton(dir_gui, text="Start Scan", command=lambda:start_dir_main(url_entry))
    dir_main_button.place(x = 225, y = 410)
    
    def open_file():
        global dir_filename
        dir_filename = filedialog.askopenfilename(initialdir = "/", title = "Select a File",
                filetypes = (("Text files", "*.txt*"), ("all files", "*.*")))
        showinfo(title="File Selected", message=dir_filename)

    def directory_buster(url):
        """directory_buster enumerates directories

        directory_buster takes a url from the user in the form of
        http://example.com and a path to the wordlist. Then using
        the requests lib prints out results based on status codes
        
        """
        # The whole function is under try/except statments to handle errors
        try:  
            url = url_entry.get()
            wordlist = dir_filename

            # Some user error handling
            if url == "":
                showwarning("Warning", "Please provide a host to scan...")
                directory_buster()
            elif wordlist == "":
                showwarning("Warning", "Please provide a wordlist...")
                directory_buster()
            elif ".txt" not in wordlist:
                showwarning("Warning", "For a wordlist use txt files...")
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
                                result_text_box.insert("insert", f"{result}\n")
                                results += result + "\n"
                        result_text_box.insert("insert", "Scan Completed..")
                    wordfile.close()
                    
                    choice = tkinter.messagebox.askquestion("Save to File", "Save to a file ?")

                    if choice == "yes":
                        gui_saving(results)

                    else:
                        directory_buster()
                    
                except FileNotFoundError as err:
                    showerror("Error", f"Error has occurred: {err}")
                    directory_buster()          

        except requests.exceptions.ConnectionError as err:
            showerror("Error", f"Error has occurred: {err}")
            directory_buster()
        except requests.exceptions.MissingSchema as err:
            showerror("Error", f"Error has occurred: {err}")
            directory_buster()

    def start_dir_main(url_entry):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=directory_buster, args=(url_entry,)).start()

def login_gui_menu():
    """login_gui_menu is a gui menu of login cracker!
    
    """
    log_gui = ctk.CTkToplevel()
    log_gui.geometry("600x450")
    log_gui.title("Directory scanner")

    log_url_label = ctk.CTkLabel(log_gui, font=("Helvetica", 14, "bold"), 
                            text="Enter an address to scan\n(ex: http://example.com/login.php)")
    log_url_label.place(x = 15, y = 20)

    log_url_entry = ctk.CTkEntry(log_gui, width=200)
    log_url_entry.place(x = 35, y = 60)

    pw_label = ctk.CTkLabel(log_gui, font=("Helvetica", 14, "bold"), 
                            text="Choose Passwordlist")
    pw_label.place(x = 50, y = 120)   

    pass_file = ctk.CTkButton(log_gui, text="Select a password file", command=lambda:open_pass())
    pass_file.place(x = 55, y = 150)

    us_label = ctk.CTkLabel(log_gui, font=("Helvetica", 14, "bold"), 
                            text="Username/Userfile location")
    us_label.place(x = 325, y = 20)

    us_entry = ctk.CTkEntry(log_gui, width=200)
    us_entry.place(x = 320, y = 60)

    result_text_box = ctk.CTkTextbox(log_gui, width=400, height=200)
    result_text_box.place(x = 100, y = 200)

    log_main_button = ctk.CTkButton(log_gui, text="Start Scan", command=lambda:start_login_main(log_url_entry, us_entry, fail_entry))
    log_main_button.place(x = 225, y = 410)

    fail_label = ctk.CTkLabel(log_gui, font=("Helvetica", 14, "bold"),
                            text="Enter login error message")
    fail_label.place(x = 325, y = 120)

    fail_entry = ctk.CTkEntry(log_gui, width=200)
    fail_entry.place(x = 320, y = 150)

    def open_pass():
        global pass_filename
        pass_filename = filedialog.askopenfilename(initialdir = "/", title = "Select a File",
                filetypes = (("Text files", "*.txt*"), ("all files", "*.*")))
        showinfo(title="File Selected", message=pass_filename)

    def login_cracker(url, user, fail):
        """login_cracker brute forces web page authentication

        Takes the full url from user input, a txt file containing
        usernames or a single user name, takes a txt password file 
        and finally a failed login message. If successfull it returns 
        the user and password.
        
        """
        # Takes the url
        url = log_url_entry.get()
        # Takes the username or userfile
        user = us_entry.get()
        # Takes the password file
        passw = pass_filename
        # Takes the fail message from the user
        fail = fail_entry.get()
        
        # Some user error handling
        if url == "":
            showwarning("Warning", "Enter a URL to scan ..")
            login_cracker()
        elif fail == "":
            showwarning("Enter the error message ..")
            login_cracker()
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
                                    result_text_box.insert("insert", f"Trying username: {user_entry}/ Password: {pass_entry}\n")
                                    if fail in request.content.decode():
                                        continue
                                    else:
                                        result_text_box.insert("insert", f"* Found Username: {user_entry} With password: {pass_entry}\n")
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
                            result_text_box.insert("insert", f"- Trying password: {entry}\n")
                            if fail in request.content.decode():
                                continue
                            else:
                                result_text_box.insert("insert", f"* Found Password: {entry} for the username: {user}\n")
                                break

            except FileNotFoundError as err:
                showerror("Error", f"Error has occurred: {err}")
                login_cracker()
            except requests.exceptions.MissingSchema as err:
                showerror("Error", f"Error has occured: {err}")
                login_cracker()
            except requests.exceptions.ConnectionError as err:
                showerror("Error", f"Error has occured: {err}")
                login_cracker()

    def start_login_main(log_url_entry, us_entry, fail_entry):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=login_cracker, args=(log_url_entry, us_entry, fail_entry,)).start()

def hash_gui_menu():
    """hash_gui_menu is gui menu of the hash cracker!
    
    """
    hash_gui = ctk.CTkToplevel()
    hash_gui.geometry("600x450")
    hash_gui.title("Hash cracker")

    hash_label = ctk.CTkLabel(hash_gui, font=("Helvetica", 14, "bold"), 
                            text="Enter a hash/hash.txt file")
    hash_label.place(x = 50, y = 20)

    hash_entry = ctk.CTkEntry(hash_gui, width=200)
    hash_entry.place(x = 35, y = 60)

    list_label = ctk.CTkLabel(hash_gui, font=("Helvetica", 14, "bold"), 
                            text="Choose a wordlist")
    list_label.place(x = 50, y = 120)   

    wrd_file = ctk.CTkButton(hash_gui, text="Select a wordlist", command=lambda:open_wrd())
    wrd_file.place(x = 55, y = 150)

    alg_label = ctk.CTkLabel(hash_gui, font=("Helvetica", 14, "bold"), 
                            text="Choose an Algorithm")
    alg_label.place(x = 350, y = 20)

    alg_entry = ctk.CTkEntry(hash_gui, width=200)
    alg_entry.place(x = 320, y = 60)

    result_text_box = ctk.CTkTextbox(hash_gui, width=400, height=200)
    result_text_box.place(x = 100, y = 200)

    # Prints out the supported hash algorithms
    result_text_box.insert("insert", f"These are suported\n{hashlib.algorithms_guaranteed}")

    hash_main_button = ctk.CTkButton(hash_gui, text="Start Crackin", command=lambda:start_hash_main(hash_entry, alg_entry))
    hash_main_button.place(x = 225, y = 410)

    def clear_text_box():
            result_text_box.delete("1.0", "end")

    def open_wrd():
        global wrd_filename
        wrd_filename = filedialog.askopenfilename(initialdir = "/", title = "Select a File",
                filetypes = (("Text files", "*.txt*"), ("all files", "*.*")))
        showinfo(title="File Selected", message=wrd_filename)

    def hash_cracker(hashCrack, alg):
        """hash_cracker tries to crack user given hashes:

            hashCrack = specify hash to crack
            wordlist = specify wordlist
            alg = specify which algorithm to use

            Then the function attempts to crack user given hash value
            with hashlib algorithms

        """

        clear_text_box()

        # Takes the hash from the user or hash file
        hashCrack = hash_entry.get()
        
        # Takes the wordlist from the user
        wordlist = wrd_filename
    
        # User inputs the algorithm
        alg = alg_entry.get()

        # Some user/error handling
        if wordlist == "":
            showwarning("Warning", "You need to provide a wordlist!")
            hash_cracker()
        elif ".txt" not in wordlist:
            showwarning("Warning", "Please provide a .txt file for the wordlist!")
            hash_cracker()
        elif hashCrack == "":
            showwarning("Warning", "Please provide a value to crack!")
            hash_cracker()
        elif alg not in hashlib.algorithms_guaranteed:
            showwarning("Warning", "Please Provide a valid algorithm")
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
                
                result_text_box.insert("insert", f"These are the results:\n{cracked}\n")
                
                choice = tkinter.messagebox.askquestion("Save to File", "Save to a file ?")

                if choice == "yes":
                    gui_saving(cracked)
                else:
                    hash_cracker()
                    
            except ValueError as err:
                showerror("Error", f"Error has occurred: {err}")
                hash_cracker()        

            except FileNotFoundError as err:
                showerror("Error", f"Error has occured: {err}")
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
                            result_text_box.insert("insert", f"Hash found: {entry.strip()}")
                            
                            choice = tkinter.messagebox.askquestion("Save to File", "Save to a file ?")

                            if choice == "yes":
                                gui_saving(one_cracked)
                            else:
                                hash_cracker()
                    
                        else:
                            pass
                    
                    # Incase hash could not be cracked user will be redirected back to the menu
                    if h.hexdigest() != hashCrack:  
                        result_text_box.insert("insert", "Could not crack the hash....")
                        hash_cracker()
            
            except FileNotFoundError as err:
                showerror("Error", f"Error has occured: {err}")
                hash_cracker()

    def start_hash_main(hash_entry, alg_entry):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=hash_cracker, args=(hash_entry, alg_entry,)).start()

def gui_saving(to_save):
    """gui_saving is the gui menu of the saving function!
    
    """
    save_gui = ctk.CTkToplevel()
    save_gui.geometry("300x300")
    save_gui.title("Save to file")

    save_file = to_save

    save_label = ctk.CTkLabel(save_gui, font=("Helvetica", 14, "bold"), text="Enter a file name to save as")
    save_label.place(x = 50, y = 50)

    save_entry = ctk.CTkEntry(save_gui, width=200)
    save_entry.place(x = 50, y = 90)

    save_button = ctk.CTkButton(save_gui, font=("Helvetica", 14, "bold"),text="Save", command=lambda:start_saving_main(save_entry, save_file))
    save_button.place(x = 80, y = 255)

    result_box = ctk.CTkTextbox(save_gui, width=200, height=100)
    result_box.place(x = 50, y = 140)
    
    def saving(file, save):
        """saving saves outputs to files

        Saving saves the output to file based on where the script
        was running from. The script itself provides what will be saved
        via the save argument. Only thing that the user provides is a file
        name!
        
        """
        file = f"{save_entry.get()}.txt"
        try:
            with open(file, mode="a") as f:
                f.write(save)
                f.close()
                result_box.insert("insert", "File saved to the directory where the script is running from!")
        except PermissionError as err:
            showerror("Error", f"Error has occurred: {err}")

    def start_saving_main(save_entry, save_file):
        """threading so the program wont crash

        Because the output has to be written out to the gui
        the program runs a thread, this way it wont crash and 
        can write out to the gui, as well run in the background!
        
        """
        threading.Thread(target=saving, args=(save_entry, save_file,)).start()

root.mainloop()