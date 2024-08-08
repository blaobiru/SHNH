import os  # import the os module
import subprocess
import sys
import time
import signal
import hashlib
from platform import system

defaultportscan = "50"

def sqlmap_automation():
    os.system("clear")  # clear screen
    print("""
    1. Database
    2. Tables
    3. Column
    4. Column Dump
    5. Dump
    6. Exit
    """)

    url = input("Enter a sql_url: ")  # for user input

    def database():
        os.system("sqlmap " + "-u " + url + " --dbs")  # show databases

    def tables():
        d_name = input("Enter a database name: ")
        os.system("sqlmap " + "-u " + url + " -D " + d_name + " --tables")  # show tables

    def col():
        d_name = input("Enter a database name: ")
        t_name = input("Enter a table name: ")
        os.system("sqlmap " + "-u " + url + " -D " + d_name + " -T " + t_name + " --columns")  # show columns

    def col_dump():
        d_name = input("Enter a database name: ")
        t_name = input("Enter a table name: ")
        c_name = input("Enter a column name: ")
        os.system("sqlmap " + "-u " + url + " -D " + d_name + " -T " + t_name + " -C " + c_name + " --dump")  # dump data

    def a_dump():
        os.system("sqlmap " + "-u " + url + " --dump")

    def main():
        choose = int(input("Enter a number: "))
        if choose == 1:
            database()
        elif choose == 2:
            tables()
        elif choose == 3:
            col()
        elif choose == 4:
            col_dump()
        elif choose == 5:
            a_dump()
        elif choose == 6:
            os.system("clear")
            print("Thank you")
            os.system("exit")
        else:
            print("Wrong choice!!")

    main()

def run_hydra(command):
    try:
        # Run the hydra command and capture output
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr.decode()}")
        print("Returning to main menu...\n")

def http_brute():
    target = input("Enter the target URL (e.g., http://example.com): ")
    userlist = input("Enter the path to the user list file: ")
    passlist = input("Enter the path to the password list file: ")
    command = f"hydra -L {userlist} -P {passlist} {target} http-post / -f"
    run_hydra(command)

def ssh_brute():
    target = input("Enter the target IP (e.g., 192.168.1.1): ")
    userlist = input("Enter the path to the user list file: ")
    passlist = input("Enter the path to the password list file: ")
    command = f"hydra -L {userlist} -P {passlist} {target} ssh"
    run_hydra(command)

def hydra_automation():
    while True:
        print("================")
        print("Hydra Automation")
        print("================")
        print("Select Service:")
        print("1. Http Brute")
        print("2. SSH Brute")
        print("3. Exit")
        print("Select: ", end="")
        
        choice = input().strip()

        if choice == '1':
            http_brute()
        elif choice == '2':
            ssh_brute()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please select again.")

def mainmenu():
    print("\n \033[1;91m your output file is in your current directory \033[1;m")
    os.system("pwd")
    print(" \033[1;91m Your current directory \033[1;m")
    print("\n \033[1;91m1-) Back to Main Menu \n 2-) Exit \033[1;m")
    choice = input("root""\033[1;91m@root:~$\033[1;m ")
    if choice == "1":
        start()
    elif choice == "2":
        print(" \033[1;91m@Good bye\033[1;m")
        sys.exit()
    else:
        print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        start()

def sigint_handler(signum, frame):
    os.system("clear")
    print("CTRL+C detected!")
    print(" \033[1;91m@Good bye\033[1;m")
    sys.exit()

signal.signal(signal.SIGINT, sigint_handler)

def menu():
    print("""
        \033[1;91m Default Scan Types \033[1;m
        1-) Default Scan
        2-) Host Discovery
        3-) Port(SYN) Scan
        4-) Port(TCP) Scan
        5-) Port(UDP) Scan
        
        \033[1;91m Vulnerability Scanning \033[1;m
        6-) Vulnerability Scanning 
        
        0-) Exit
        """)

def start():
    menu()
    print("   Enter one of the options.")

    choose = input("root""\033[1;91m@root:~$\033[1;m ")

    if choose == "1":
        print(" Starting Default Scan...")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target1 = input("     Enter Your Destination: ")
        if not target1:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport1 = input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport1:
                os.system("nmap -vv --top-ports=" + defaultportscan + " " + target1 + " -oN " + target1)
            else:
                os.system("nmap -vv --top-ports=" + topport1 + " " + target1 + " -oN " + target1)
            
        mainmenu()

    elif choose == "2":
        print(" Starting Host Discovery...")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target2 = input("     Enter Your Destination: ")
        if not target2:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport2 = input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport2:
                os.system("nmap -vv -Pn --top-ports=" + defaultportscan + " " + target2 + " -oN HostD-" + target2 + "-output")
            else:
                os.system("nmap -vv -Pn --top-ports=" + topport2 + " " + target2 + " -oN HostD-" + target2 + "-output")
            
        mainmenu()
    
    elif choose == "3":
        print(" Starting Port(SYN) Scan...")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target3 = input("     Enter Your Destination: ")
        if not target3:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport3 = input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport3:
                os.system("nmap -vv -sS --top-ports=" + defaultportscan + " " + target3 + " -oN " + target3 + "-output")
            else:
                os.system("nmap -vv -sS --top-ports=" + topport3 + " " + target3 + " -oN " + target3 + "-output")

        mainmenu()
    
    elif choose == "4":
        print(" Starting Port(TCP) Scan...")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target4 = input("     Enter Your Destination: ")
        if not target4:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport4 = input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport4:
                os.system("nmap -vv -sT --top-ports=" + defaultportscan + " " + target4 + " -oN TcpScan-" + target4 + "-output")
            else:
                os.system("nmap -vv -sT --top-ports=" + topport4 + " " + target4 + " -oN TcpScan-" + target4 + "-output")

        mainmenu()
    
    elif choose == "5":
        print(" Starting Port(UDP) Scan...")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target5 = input("     Enter Your Destination: ")
        if not target5:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport5 = input("Top Port? Example: 10 or 50, Default 50:  ")
            if not topport5:
                os.system("nmap -vv -sU --top-ports=" + defaultportscan + " " + target5 + " -oN UdpScan-" + target5 + "-output")
            else:
                os.system("nmap -vv -sU --top-ports=" + topport5 + " " + target5 + " -oN UdpScan-" + target5 + "-output")
            
        mainmenu()

    elif choose == "6":
        print("Vulnerability Scanning")
        time.sleep(1)
        os.system("clear")
        print(" Enter your IP address or example.com")
        print("")
        target6 = input("     Enter Your Destination: ")
        if not target6:
            print("Pls Enter Target")
            print("\033[1;91mGo to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            start()
        else:
            topport6 = input("\033[92mTop Port? Example 10 or 50, Default 50:\033[0m;  ")
            if not topport6:
                os.system("nmap -vv -sV -ff -Pn --top-ports=" + defaultportscan + " --script vuln " + target6 + " -oN " + "VulnScanDef-" + target6 + "-output")
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports=" + topport6 + " --script vuln " + target6 + " -oN " + "VulnScanDef-" + target6 + "-output")
        
        mainmenu()

    elif choose == "0":
        print(" \033[1;91m@Good bye\033[1;m")
        sys.exit()

    else:
        print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        start()

def nmap_automation():
    if os.geteuid() == 0:
        start()
    else:
        print("Please run it with root access.")
        sys.exit()

def identify_hash_type(hash_value):
    hash_length = len(hash_value)
    if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 64:
        return "SHA256"
    elif hash_length == 128:
        return "SHA512"
    else:
        return "Unknown"

def crack_hash_password(hash_value, dictionary_file):
    hash_type = identify_hash_type(hash_value)
    if hash_type == "Unknown":
        print("Unsupported hash type.")
        return

    try:
        with open(dictionary_file, 'r') as file:
            for line in file:
                password = line.strip()
                if hash_type == "MD5":
                    hash_object = hashlib.md5(password.encode())
                elif hash_type == "SHA1":
                    hash_object = hashlib.sha1(password.encode())
                elif hash_type == "SHA256":
                    hash_object = hashlib.sha256(password.encode())
                elif hash_type == "SHA512":
                    hash_object = hashlib.sha512(password.encode())

                hashed_password = hash_object.hexdigest()
                if hashed_password == hash_value:
                    print(f"Password found: {password}")
                    return
            print("Password not found in the dictionary.")
    except FileNotFoundError:
        print(f"File not found: {dictionary_file}")

def hashcat_automation():
    while True:
        print("\nMain Menu")
        print("1. Identify Hash")
        print("2. Crack Hash Password")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            hash_value = input("Enter the hash: ")
            hash_type = identify_hash_type(hash_value)
            print(f"The hash type is: {hash_type}")

        elif choice == '2':
            hash_value = input("Enter the hash to crack: ")
            dictionary_file = input("Enter the path to the dictionary file: ")
            crack_hash_password(hash_value, dictionary_file)

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

def main_menu():
    while True:
        print("=====================")
        print("Welcome")
        print("=====================")
        print("Select Service:")
        print("1. SQLmap Automation")
        print("2. Hydra Automation")
        print("3. Nmap Automation")
        print("4. Hashcat Automation")
        print("5. Exit")
        print("=====================")

        choice = int(input("Select Service: "))

        if choice == 1:
            sqlmap_automation()
        elif choice == 2:
            hydra_automation()
        elif choice == 3:
            nmap_automation()
        elif choice == 4:
            hashcat_automation()
        elif choice == 5:
            print("Exiting. Thank you for using this service.")
            break
        else:
            print("Invalid choice. Please select a valid service.")

if __name__ == "__main__":
    main_menu()
