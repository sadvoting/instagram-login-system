from colorama import Fore
import requests, platform, time, os, sys, base64, re, subprocess


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
   
class InstagramClient:
    def __init__(self, username, password):
        self.session = requests.Session()
        self.username = username
        self.password = password
        self.base_url = "https://i.instagram.com/api/v1/bloks/apps/"
        self.base_deviceid = "android-ec40bd6622ac9b21"
        self.base_machineid = "Z5d97AABAAF0xC3_hhRHvlrYSyrM"
        self.base_header_deviceid = "552233dc-9663-4973-82bc-b00ad110137a" # Random UUID cause issues with Secure Code
        self.base_header_family_deviceid = "d660a764-9ea5-4f2a-a358-ea3d5fa4bd8f" # Random UUID cause issues with Secure Code
        self.base_useragent = "Instagram 361.0.0.46.88 Android (28/9; 300dpi; 900x1600; Asus; ASUS_Z01QD; ASUS_Z01QD; intel; en_US; 674675155)"
        self.base_blocks_versioning_id = "16e9197b928710eafdf1e803935ed8c450a1a2e3eb696bff1184df088b900bcf"
        self.session.headers.update({"User-Agent": self.base_useragent})

    def send_request(self, method, url, data=None, headers=None, allow_redirects=True):
        return self.session.request(
            method=method, 
            url=url, 
            data=data, 
            headers=headers, 
            allow_redirects=allow_redirects
        )

    def send_login_request(self, password, username):
        payload = f'''params={{"client_input_params":{{"should_show_nested_nta_from_aymh":0,"device_id":"{self.base_deviceid}","sim_phones":[],"login_attempt_count":1,"secure_family_device_id":"","machine_id":"{self.base_machineid}","accounts_list":[{{"credential_type":"google_oauth","account_type":"google_oauth","token":""}}],"auth_secure_device_id":"","has_whatsapp_installed":0,"password":"#PWD_INSTAGRAM:0:{int(time.time())}:{password}","sso_token_map_json_string":"","family_device_id":"{self.base_header_family_deviceid}","fb_ig_device_id":[],"device_emails":[],"try_num":1,"lois_settings":{{"lois_token":"","lara_override":""}},"event_flow":"login_manual","event_step":"home_page","headers_infra_flow_id":"","openid_tokens":{{"":""}},"client_known_key_hash":"","contact_point":"{username}","encrypted_msisdn":""}},"server_params":{{"should_trigger_override_login_2fa_action":0,"is_from_logged_out":0,"should_trigger_override_login_success_action":0,"login_credential_type":"none","server_login_source":"login","waterfall_id":"92fc8f96-b655-4d79-8e0b-70a51d8a16cd","login_source":"Login","is_platform_login":0,"INTERNAL__latency_qpl_marker_id":36707139,"offline_experiment_group":"caa_iteration_v3_perf_ig_4","is_from_landing_page":0,"password_text_input_id":"e5bwah:133","is_from_empty_password":0,"ar_event_source":"login_home_page","qe_device_id":"{self.base_header_deviceid}","username_text_input_id":"e5bwah:132","layered_homepage_experiment_group":null,"device_id":"{self.base_deviceid}","INTERNAL__latency_qpl_instance_id":8.5547960900377E13,"reg_flow_source":"login_home_native_integration_point","is_caa_perf_enabled":1,"credential_type":"password","is_from_password_entry_page":0}}}}&bloks_versioning_id={self.base_blocks_versioning_id}'''

        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f'{self.base_url}com.bloks.www.bloks.caa.login.async.send_login_request/',
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "IG-Set-Authorization" in response_body or "logged_in_user" in response_body:
            match = re.search(r'IG-Set-Authorization\\\\\\\\\\\\\\": \\\\\\\\\\\\\\"(.*?)\\\\\\\\\\\\\\"', response_body)
            if match:
                return match.group(1), ""
            return "bad request", response_body
        elif any(x in response_body for x in ["Unable to log in", "login_failure", "No account found", "account_recovery"]):
            return "bad credentials", ""
        elif "redirection_to_two_fac" in response_body:
            match = re.search(r'\\"INTERNAL_INFRA_screen_id\\"\).*?Make, \\"(.*?)\\", \\"two_factor_login\\"', response_body)
            if match:
                self.current_data_context = match.group(1)
                return "2FA", ""
            match = re.search(r'\\"INTERNAL_INFRA_THEME\\"\).*?Make, \\"(.*?)\\", \\"two_factor_login\\"', response_body)
            if match:
                self.current_data_context = match.group(1)
                return "2FA", ""
            return "bad request", response_body 
        elif "override_login_2fa_action" in response_body and "INTERNAL_INFRA_THEME" in response_body:
            match = re.search(r'\\"INTERNAL_INFRA_THEME\\".*?Make, \\"(.*?)\\", \\"harm_f', response_body)
            if match:
                self.current_data_context = match.group(1)
                return "2FA", ""
            return "bad request", response_body
        elif "override_login_2fa_action" in response_body and "challenge_context" in response_body:
            url_pattern = r'\\\\\\"url\\\\\\":\\\\\\"(.*?)\\\\\\",\\\\\\"api_path'
            context_pattern = r'\\\\\\"challenge_context\\\\\\":\\\\\\"(.*?)\\\\\\"}}}\\", \(bk.action.'

            url_match = re.search(url_pattern, response_body)
            context_match = re.search(context_pattern, response_body)

            challenge_url = url_match.group(1) if url_match else None
            challenge_context = context_match.group(1) if context_match else None
           
            if challenge_url is not None and challenge_context is not None:
                self.current_header_mid = res.headers.get('ig-set-x-mid')
                self.current_data_context = challenge_context
                self.current_challange_url = challenge_url.replace("\\\\\\", "")
                return "challenge", ""
            
            return "bad request", response_body
        elif "override_login_2fa_action" in response_body or "INTERNAL_INFRA_THEME" not in response_body:
            match = re.search(r'\\"device_id\\".*?Make, \\"(.*?)\\", \\"', response_body)
            if match:
                self.current_data_context = match.group(1)
                return "secure", ""
            return "bad request", response_body
        else:
            return "bad request", response_body

    def enter_2fa_code_request(self, code):
        payload = f'''params={{"client_input_params":{{"auth_secure_device_id":"","machine_id":"{self.base_machineid}","code":"{code}","should_trust_device":1,"family_device_id":"{self.base_header_family_deviceid}","device_id":"{self.base_deviceid}"}},"server_params":{{"INTERNAL__latency_qpl_marker_id":36707139,"device_id":"{self.base_deviceid}","challenge":"totp","machine_id":null,"INTERNAL__latency_qpl_instance_id":2.7604101900059E13,"two_step_verification_context":"{self.current_data_context}","flow_source":"two_factor_login"}}}}&bloks_versioning_id={self.base_blocks_versioning_id}'''

        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.bloks.www.two_step_verification.verify_code.async/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "IG-Set-Authorization" in response_body or "logged_in_user" in response_body:
            match = re.search(r'IG-Set-Authorization\\\\\\\\\\\\\\": \\\\\\\\\\\\\\"(.*?)\\\\\\\\\\\\\\"', response_body)
            if match:
                return match.group(1), ""
            return "bad request", response_body
        elif "security code and try again" in response_body:
            return "invalid", ""
        else:
            return "bad request", response_body

    def send_manual_accept_request(self):
        payload = f'''params={{"client_input_params":{{"auth_secure_device_id":"","machine_id":"{self.base_machineid}","family_device_id":"{self.base_header_family_deviceid}","device_id":"{self.base_deviceid}"}},"server_params":{{"machine_id":null,"INTERNAL__latency_qpl_marker_id":36707139,"INTERNAL__latency_qpl_instance_id":2.2783007900294E13,"device_id":"{self.base_deviceid}","two_step_verification_context":"{self.current_data_context}","flow_source":"two_factor_login"}}}}&bk_client_context={{"bloks_version":"{self.base_blocks_versioning_id}","styles_id":"instagram"}}&bloks_versioning_id={self.base_blocks_versioning_id}'''       
        
        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.bloks.www.two_step_verification.has_been_allowed.async/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "IG-Set-Authorization" in response_body or "logged_in_user" in response_body:
            match = re.search(r'IG-Set-Authorization\\\\\\\\\\\\\\": \\\\\\\\\\\\\\"(.*?)\\\\\\\\\\\\\\"', response_body)
            if match:
                return match.group(1), ""
            return "bad request", response_body
        elif "challenged_device_denied" in response_body:
            return "denied", ""
        elif "two_step_verification" in response_body:
            return "no action", ""
        else:
            return "bad request", response_body

    def send_secure_code_request(self):

        payload = f'''params={{"client_input_params":{{"auth_secure_device_id":"","has_whatsapp_installed":0,"machine_id":"{self.base_machineid}","family_device_id":"{self.base_header_family_deviceid}"}},"server_params":{{"context_data":"{self.current_data_context}","INTERNAL__latency_qpl_marker_id":36707139,"INTERNAL__latency_qpl_instance_id":1.12364533900003E14,"device_id":"{self.base_header_deviceid}"}}}}&bk_client_context={{"bloks_version":"{self.base_blocks_versioning_id}","styles_id":"instagram"}}&bloks_versioning_id={self.base_blocks_versioning_id}'''       

        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.bloks.www.ap.two_step_verification.entrypoint_async/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "two_step_verification.code_entry" not in response_body:
            return "bad request", response_body
        else: 
            match = re.search(r'\\"device_id\\".*?Make, \\"(.*?)\\", \\"', response_body)
            if match:
                self.current_data_context = match.group(1)
            else:
                return "bad request", response_body


        payload = f'''params={{"server_params":{{"device_id":"{self.base_header_deviceid}","context_data":"{self.current_data_context}","INTERNAL_INFRA_screen_id":"generic_code_entry"}}}}&bloks_versioning_id={self.base_blocks_versioning_id}'''       

        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.bloks.www.ap.two_step_verification.code_entry/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "the code we sent" in response_body :
            match = re.search(r'"Enter the code we sent to (.*?)","*"', response_body)
            if match:
                match2 = re.search(r'\\"device_id\\".*?Make, \\"(.*?)\\", \\"', response_body)
                if match2:
                    self.current_data_context = match2.group(1)
                    return match.group(1), ""
            return "bad request", response_body
        else:
            return "bad request", response_body
        
    def enter_secure_code_request(self, code):
        payload = f'''params={{"client_input_params":{{"auth_secure_device_id":"","machine_id":"{self.base_machineid}","code":"{code}","family_device_id":"{self.base_header_family_deviceid}","device_id":"{self.base_deviceid}"}},"server_params":{{"context_data":"{self.current_data_context}","INTERNAL__latency_qpl_marker_id":36707139,"INTERNAL__latency_qpl_instance_id":1.44172662300254E14,"device_id":"{self.base_header_deviceid}"}}}}&bk_client_context={{"bloks_version":"{self.base_blocks_versioning_id}","styles_id":"instagram"}}&bloks_versioning_id={self.base_blocks_versioning_id}'''

        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.bloks.www.ap.two_step_verification.code_entry_async/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text
        
        if "IG-Set-Authorization" in response_body or "logged_in_user" in response_body:
            match = re.search(r'IG-Set-Authorization\\\\\\\\\\\\\\": \\\\\\\\\\\\\\"(.*?)\\\\\\\\\\\\\\"', response_body)
            if match:
                return match.group(1), ""
            return "bad request", response_body
        elif "code validation" in response_body:
            return "invalid", ""
        else:
            return "bad request", response_body

    def get_secure_challange_request(self):
        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "X-Mid":                 self.current_header_mid,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="GET",
            url=f"{self.current_challange_url.replace('https://i.instagram.com/challenge/', 'https://i.instagram.com/api/v1/challenge/')}?guid={self.base_header_deviceid}&device_id={self.base_deviceid}&challenge_context={self.current_data_context}",     
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "select_verify_method" in response_body:
            context_match = re.search(r'"challenge_context":"(.*?)"', response_body)
            challenge_context = context_match.group(1) if context_match else None

            # Extract nonce_code
            nonce_match = re.search(r'"nonce_code":"(.*?)"', response_body)
            nonce_code = nonce_match.group(1) if nonce_match else None

            if challenge_context is not None and nonce_code is not None:
                self.current_data_context = challenge_context
                self.current_nonce_code = nonce_code
                return "secure", ""
            return "bad request", response_body
        else:
            return "bad request", response_body

    def send_secure_challange_code_request(self):


        payload = f'''choice=1&has_follow_up_screens=0&bk_client_context={{"bloks_version":"{self.base_blocks_versioning_id}","styles_id":"instagram"}}&challenge_context={self.current_data_context}&bloks_versioning_id={self.base_blocks_versioning_id}'''
        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "X-Mid":                 self.current_header_mid,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.instagram.challenge.navigation.take_challenge/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "code we sent" in response_body :
            match = re.search(r'\(bk\.action\.array\.Make, \\"Enter the 6-digit code we sent to\\", \\"16sp\\", \\"center\\".*?\(bk\.action\.map\.Make, \(bk\.action\.array\.Make, \\"\\\\u3417\\"\),.*?\(bk\.action\.array\.Make, \\"(.*?\*\*\*.*?)\\", \\"16sp\\", \\"bold\\", \\"center\\"', response_body)
            if match:
                return match.group(1).replace(')\\", \\"-\\", \\".\\", \\"*\\"), (bk.action.array.Make, \\"', ""), ""
            return "bad request", response_body
        else:
            return "bad request", response_body

    def enter_secure_challange_code_request(self, code):
        
        payload = f'''security_code={code}&perf_logging_id=1456832077&has_follow_up_screens=0&bk_client_context=%7B%22bloks_version%22%3A%22{self.base_blocks_versioning_id}%22%2C%22styles_id%22%3A%22instagram%22%7D&challenge_context={self.current_data_context}&bloks_versioning_id={self.base_blocks_versioning_id}'''       
       
        headers = {
            "Host":                  "i.instagram.com",
            "X-Ig-Device-Id":        self.base_header_deviceid,
            "X-Ig-Family-Device-Id": self.base_header_family_deviceid,
            "X-Bloks-Version-Id":    self.base_blocks_versioning_id,
            "User-Agent":            self.base_useragent,
            "X-Mid":                 self.current_header_mid,
            "Content-Type":          "application/x-www-form-urlencoded; charset=UTF-8",
        }

        res = self.send_request(
            method="POST",
            url=f"{self.base_url}com.instagram.challenge.navigation.take_challenge/",
            data=payload.encode("utf-8"),
            headers=headers,
            allow_redirects=False
        )

        response_body = res.text

        if "profile_pic_url" in response_body or "fbid_v2" in response_body:
            return res.headers.get('ig-set-authorization'), ""
        elif "check the code we sent" in response_body:
            return "invalid", ""
        else:
            return "bad request", response_body


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
        security_validation_2_logic(IGClient, username)
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
            contact_address = result
            while True:
                clear()

                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

                print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Code Sent to {contact_address}")
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
  
def security_validation_2_logic(IGClient, username):

    clear()

    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
    print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

        
    print(f"{Fore.YELLOW}({Fore.WHITE}!{Fore.YELLOW}){Fore.WHITE} Secure Detected ..\n")

    result, response = IGClient.get_secure_challange_request()
    if result == "bad request":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Failed to get Secure Challange Data.\n{response}")
        time.sleep(3)
        sys.exit()

    result, response = IGClient.send_secure_challange_code_request()
    if result == "bad request":
        print(f"{Fore.RED}({Fore.WHITE}!{Fore.RED}){Fore.WHITE} Exception Occured.\n{response}")
        time.sleep(3)
        sys.exit()
    else:
        contact_address = result
        while True:
            clear()

            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Welcome Boss!")    
            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Developed by https://github.com/sadvoting/ \n")

            print(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Code Sent to {contact_address}")
            code = input(f"{Fore.CYAN}({Fore.WHITE}+{Fore.CYAN}){Fore.WHITE} Enter Secure Code: ")
            result, response = IGClient.enter_secure_challange_code_request(code)
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


if __name__ == "__main__":
    main()
