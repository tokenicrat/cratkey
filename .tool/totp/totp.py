import json
import os
import sys
import time
import select
import termios
import tty
import pyotp
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# File storage
TOTP_FILE = ".data/totp/key.json"

# ANSI color codes
COLOR_INFO = "\033[96m"
COLOR_HEADER = "\033[94m"
COLOR_SUCCESS = "\033[92m"
COLOR_RESET = "\033[0m"

def custom_getpass(prompt="Password: "):
    print(prompt, end='', flush=True)
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        password = ""
        while True:
            ch = sys.stdin.read(1)
            if ch == '\n' or ch == '\r':
                break
            elif ch == '\x7f':
                password = password[:-1]
                sys.stdout.write('\b \b')
            else:
                password += ch
                sys.stdout.write('*')
            sys.stdout.flush()
        print()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password

def custom_sha256(data: str) -> bytes:
    return sha256(data.encode()).digest()

def custom_base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def custom_base64_decode(data: str) -> bytes:
    return base64.b64decode(data)

def custom_encrypt(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data.encode(), AES.block_size))
    return custom_base64_encode(encrypted_data)

def custom_decrypt(data: str, key: bytes) -> str:
    raw_data = custom_base64_decode(data)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

def get_master_password(data, field):
    """
    If data is empty, prompt user to create a new master password.
    If data is populated, prompt user to enter the master password and verify it
    by decrypting an existing entry in the specified field.
    """
    if not data:
        while True:
            pw1 = custom_getpass("Create new master password: ")
            pw2 = custom_getpass("Retype master password: ")
            if pw1 == "" or pw1 != pw2:
                print(f"{COLOR_INFO}Passwords do not match or cannot be empty. Try again.{COLOR_RESET}")
            else:
                return pw1
    else:
        while True:
            master_password = custom_getpass("Master password: ")
            key_hash = custom_sha256(master_password)
            sample_entry = next(iter(data.values()))
            try:
                custom_decrypt(sample_entry[field], key_hash)
                return master_password
            except Exception:
                print(f"{COLOR_INFO}Master password incorrect. Please try again.{COLOR_RESET}")

def load_data():
    if not os.path.exists(TOTP_FILE):
        save_data({})
    try:
        with open(TOTP_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        save_data({})
        return {}

def save_data(data):
    with open(TOTP_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_entry():
    data = load_data()
    name = input("Service name: ")
    key = input("TOTP secret key: ")
    digit = input("Digits (default 6): ") or "6"
    period = input("Period (default 30s): ") or "30"
    # use new master password function; field name for totp file is "KEY"
    master_password = get_master_password(data, "KEY")
    key_hash = custom_sha256(master_password)
    data[name] = {"KEY": custom_encrypt(key, key_hash), "DIGIT": digit, "PERIOD": period}
    save_data(data)

def delete_entry():
    data = load_data()
    name = input("Service name to delete: ")
    if name in data:
        del data[name]
        save_data(data)

def modify_entry():
    delete_entry()
    add_entry()

def is_key_pressed():
    return select.select([sys.stdin], [], [], 0)[0]

def generate_totp():
    data = load_data()
    if not data:
        return
    # prompt and verify master password using the "KEY" field
    master_password = get_master_password(data, "KEY")
    key_hash = custom_sha256(master_password)
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{COLOR_INFO}Press 'q' to exit{COLOR_RESET}")
            print(f"{COLOR_HEADER}+-----------------+------------+------------+{COLOR_RESET}")
            print(f"{COLOR_HEADER}| Service         | TOTP Code  | Expires in |{COLOR_RESET}")
            print(f"{COLOR_HEADER}+-----------------+------------+------------+{COLOR_RESET}")
            for name, details in data.items():
                try:
                    decrypted_key = custom_decrypt(details["KEY"], key_hash)
                except Exception as e:
                    print(f"{COLOR_INFO}Failed to decrypt a key for service {name}. Check your master password.{COLOR_RESET}")
                    continue
                totp = pyotp.TOTP(decrypted_key, digits=int(details["DIGIT"]), interval=int(details["PERIOD"]))
                expires_in = str(int(totp.interval - (time.time() % totp.interval)))
                print(f"{COLOR_SUCCESS}| {name.ljust(15)} | {totp.now().ljust(10)} | {expires_in.ljust(10)} |{COLOR_RESET}")
            print(f"{COLOR_HEADER}+-----------------+------------+------------+{COLOR_RESET}")
            time.sleep(1)
            if is_key_pressed() and sys.stdin.read(1).lower() == 'q':
                break
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "add":
            add_entry()
        elif sys.argv[1] == "delete":
            delete_entry()
        elif sys.argv[1] == "modify":
            modify_entry()
    else:
        generate_totp()
