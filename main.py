from colorama import Fore
from instagram import InstagramClient
import platform, time, os, sys, base64, re, subprocess


if platform.system().lower() == "windows":
    import ctypes
    ctypes.windll.kernel32.SetConsoleTitleW("$| Instagram Login Script")

def clear():
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear')

def restart():
    python = sys.executable
    subprocess.call([python] + sys.argv)
    sys.exit(0)

def show_and_save_info(auth_token, username):
    encoded_part = auth_token.split("Bearer IGT:2:")[1]
    try:
        decoded_bytes = base64.b64decode(encoded_part)
        decoded_string = decoded_bytes.decode('utf-8')
        match = re.search(r'"sessionid":"([^"]+)"', decoded_string)
        if match:
            session_id = match.group(1)
            print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Successfully logged-in to @{username}")
            print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Session ID: \n{session_id}")
            print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Authorization Token: \n{auth_token}")
            with open(f'@{username} Info.txt', "w") as file:
                file.write(f"Username: {username}\n")
                file.write(f"Session ID: {session_id}\n")
                file.write(f"Authorization Token: {auth_token}\n")
            time.sleep(3)
            sys.exit()
        else:
            print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Successfully logged-in to @{username}")
            print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Authorization Token: \n{auth_token}")
            with open(f'@{username} Info.txt', "w") as file:
                file.write(f"Username: {username}\n")
                file.write(f"Authorization Token: {auth_token}\n")
            time.sleep(3)
            sys.exit()
    except Exception:
        print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Successfully logged-in to @{username}")
        print(f"{Fore.GREEN}({Fore.WHITE}+{Fore.GREEN}){Fore.WHITE} Authorization Token: \n{auth_token}")
        with open(f'@{username} Info.txt', "w") as file:
            file.write(f"Username: {username}\n")
            file.write(f"Authorization Token: {auth_token}\n")
        time.sleep(3)
        sys.exit()
   
def main(): 

    clear()

    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

    username = input(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Enter Username: ")
    if username == "":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Username cann't be empty")
        time.sleep(3)
        restart()

    password = input(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Enter Password: ")
    if password == "":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Password cann't be empty")
        time.sleep(3)
        restart()

    print() # Split Between Results and Inputs

    IGClient = InstagramClient(username, password)
    result, response = IGClient.send_login_request(password, username)
    if result == "bad request":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
        time.sleep(3)
        choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
        if "y" in choice:
            restart()
        else:
            sys.exit()
    elif result == "2FA":
        two_factor_logic(IGClient, username)        
    elif result == "secure":
     security_validation_logic(IGClient, username)
    elif result == "bad credentials":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Invalid Credentials")
        time.sleep(3)
        choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
        if "y" in choice:
            restart()
        else:
            sys.exit()
    elif result == "challenge":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Challenge Required")
        time.sleep(3)
        sys.exit()
    else:
        show_and_save_info(result, username)

def two_factor_logic(IGClient, username):

    clear()

    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

        
    print(f"{Fore.YELLOW}({Fore.WHITE}!{Fore.YELLOW}){Fore.WHITE} 2FA Detected ..\n")

    print(f"{Fore.WHITE}1{Fore.CYAN}){Fore.WHITE} Enter 2FA Code")
    print(f"{Fore.WHITE}2{Fore.CYAN}){Fore.WHITE} Accept Manually")
    print(f"{Fore.WHITE}3{Fore.CYAN}){Fore.WHITE} Cancle")

    choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Choose an option: ")
    if choice == "1":
         while True:
            clear()

            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

            code = input(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Enter 2FA Code: ")
            result, response = IGClient.enter_2fa_code_request(code)
            if result == "bad request":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
                time.sleep(3)
                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            elif result == "invalid":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Invalid 2FA Code")
                time.sleep(3)

                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            else:
                show_and_save_info(result, username)
    elif choice == "2":
        while True:
            clear()

            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

            result, response = IGClient.send_manual_accept_request()
            if result == "bad request":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
                time.sleep(3)
                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            elif result == "denied":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} 2FA Denied")
                time.sleep(3)
                sys.exit()
            elif result == "no action":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} No Action Taken Yet")
                time.sleep(3)
                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            else:
                show_and_save_info(result, username)
    else:
        sys.exit()

def security_validation_logic(IGClient, username):

    clear()

    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

        
    print(f"{Fore.YELLOW}({Fore.WHITE}!{Fore.YELLOW}){Fore.WHITE} Secure Detected ..\n")

    print(f"{Fore.WHITE}1{Fore.CYAN}){Fore.WHITE} Enter Secure Code")
    print(f"{Fore.WHITE}2{Fore.CYAN}){Fore.WHITE} Accept Manually")
    print(f"{Fore.WHITE}3{Fore.CYAN}){Fore.WHITE} Cancle")

    choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Choose an option: ")
    if choice == "1":
        result, response = IGClient.send_secure_code_request()
        if result == "bad request":
            print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
            time.sleep(3)
            sys.exit()
        else:
            while True:
                clear()

                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Code Sent to {result}")
                code = input(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Enter Secure Code: ")
                result, response = IGClient.enter_secure_code_request(code)
                if result == "bad request":
                    print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
                    time.sleep(3)
                    choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                    if "y" in choice:
                        continue
                    else:
                        sys.exit()
                elif result == "invalid":
                    print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Invalid Secure Code")
                    time.sleep(3)

                    choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                    if "y" in choice:
                        continue
                    else:
                        sys.exit()
                else:
                    show_and_save_info(result, username)
    elif choice == "2":
        while True:
            clear()

            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

            result, response = IGClient.send_manual_accept_request()
            if result == "bad request":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
                time.sleep(3)
                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            elif result == "denied":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Secure Login Denied")
                time.sleep(3)
                sys.exit()
            elif result == "no action":
                print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} No Action Taken Yet")
                time.sleep(3)
                choice = input(f"{Fore.CYAN}({Fore.WHITE}?{Fore.CYAN}){Fore.WHITE} Do you want to try again? (y/n): ").lower()
                if "y" in choice:
                    continue
                else:
                    sys.exit()
            else:
                show_and_save_info(result, username)
    else:
        sys.exit()
  
if __name__ == "__main__":
    main()