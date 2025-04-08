# 🚀 Nova\_Observer - Total Recon & Exploit Scanner

> *"Observe the unseen. Exploit the ignored. Leave no logs behind."*

Nova\_Observer is a **next-gen automated reconnaissance and vulnerability scanner** built for professionals, hackers, and digital rebels. It combines payload injection, directory traversal, port scanning, and passive Shodan analysis into one sleek, multithreaded weapon.

**🧪 Version: β (Beta)** — Expect rapid feature growth, edge-case chaos, and new madness every update.

---

## 🔥 Features

✅ **Payload Injection Scan** - Hunt for command injection flaws like a ghost in the machine.\
✅ **Traversal Scanner** - Reveal hidden files, misconfigs, and forgotten dev entries.\
✅ **Port Scanner** - Raw socket-based lightning port scans.\
✅ **User-Agent Faker** - Rotate real-world UAs like a digital chameleon.\
✅ **Shodan Passive Recon** - Fetch vulnerable data from the shadows.\
✅ **Markdown Report Generation** - Clean, elegant, and detailed logs.\
✅ **Threaded Engine** - Perform multiple scans simultaneously without breaking a sweat.\
✅ **No Dependencies** - Pure Python 3. No BS. No bloat.

---

## ⚙️ Usage

```bash
python3 nova_observer.py -url <target_url> [options]
```

### 🔗 Required:

- `-url <target_url>` : The URL of the target you want to inspect.

### ⚙️ Optional Flags:

- `-p <port>` : Use a custom port.
- `-m <method>` : HTTP Method (GET/POST, default: GET).
- `-s <status_codes>` : Additional status codes considered valid.
- `-payw <path>` : Path to custom payload wordlist.
- `-traw <path>` : Path to directory traversal wordlist.
- `-cua <path>` : Path to custom User-Agent list.
- `-ps <start> <end>` : Port scan range (default: 20–80).
- `-t <threads>` : Number of threads (default: 4).

---

## 💣 Example Attack

```bash
python3 nova_observer.py -url https://example.com -m POST \
  -payw ./payloads.txt -traw ./traversal.txt \
  -cua ./useragents.txt -ps 1 1000 -t 8
```

---

## 📂 Output Structure

🗂 `Payload_logs/` – Logs for tested payloads.\
🗂 `Traversal_Logs/` – Logs for successful traversal checks.\
🗂 `Port_Scan_Logs/` – Open port results.\
🗂 `Err_Checked_logs/` – Errors & stack traces.\
🗂 `Report_Logs/` – Final summarized Markdown report.

---

## 🧾 Example Markdown Report Output

### 🗓️ Target Information

```
date : 2025_4-8_12-45
Scan_Targets : https://example.com
```

### 🔧 Used Method & Tools

```
- Payload_Checkers
- Multi_Traversal
- Port_Scan
- API [ shodan : https://internetdb.shodan.io/ ]
```

### 🧪 Payload Checkers

```
- Ports : 443
- Status_List : {"200", "301", "302"}
- Method : GET
- Wordlist : default_commad_injection_method_list
```

### 🎯 Detection Results

```
- True : 2
- False : 18
```

### 📜 Detected Payloads

```
- cat /etc/passwd
- ; ls -laR /etc
```

### 📁 Multi Traversal

```
- Wordlist : default_common_method_list
- [GET/200] https://example.com/../../../../etc/passwd
- [GET/200] https://example.com/.git/config
```

### 📡 Port Scan

```
- http/80
- https/443
- ssh/22
```

### 🌐 Shodan Scan

```
**[InternetDB Shodan API](https://internetdb.shodan.io/93.184.216.34)**
- CPE : ['cpe:/a:apache:http_server']
- HostName : ['example.com']
- IP : 93.184.216.34
- Ports : [80, 443]
- Tags : ['http', 'ssl']
- Vulns : ['CVE-2021-41773']
```

---

## 📜 License

MIT License — Free for all warriors of the net.

---

## 👤 Author

**Alecto\_Fsociety**\
🔗 GitHub: [@Alecto-Fsociety](https://github.com/Alecto-Fsociety)

---

## 🎨 Epic Banner

```
     __                    ___ _                                 
  /\ \ \_____   ____ _    /___\ |__  ___  ___ _ ____   _____ _ __ 
 /  \/ / _ \ \ / / _` |  //  // '_ \/ __|/ _ \ '__\ \ / / _ \ '__|
/ /\  / (_) \ V / (_| | / \_//| |_) \__ \  __/ |   \ V /  __/ |   
\_\ \/ \___/ \_/ \__,_| \___/ |_.__/|___/\___|_|    \_/ \___|_|   
                                                                 
Version β
by Alecto_Fsociety
```

---

> Stay sharp. Stay stealthy.\
> Curiosity isn't a trait — it's your root access.\
> Launch Nova\_Observer. Let entropy begin.

