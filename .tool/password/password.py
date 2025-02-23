import json
import os
import sys
import termios
import tty
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# File storage
PASSWORD_FILE = ".data/password/key.json"

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
                # Try decrypting to verify the password
                custom_decrypt(sample_entry[field], key_hash)
                return master_password
            except Exception:
                print(f"{COLOR_INFO}Master password incorrect. Please try again.{COLOR_RESET}")

def load_data():
    if not os.path.exists(PASSWORD_FILE):
        save_data({})
    try:
        with open(PASSWORD_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        save_data({})
        return {}

def save_data(data):
    with open(PASSWORD_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_entry():
    data = load_data()
    name = input("Service name: ")
    username = input("Username: ")
    password = input("Password: ")
    # use the new master password function; field name for password file is "PASSWORD"
    master_password = get_master_password(data, "PASSWORD")
    key_hash = custom_sha256(master_password)
    data[name] = {"USERNAME": username, "PASSWORD": custom_encrypt(password, key_hash)}
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

def retrieve_entry():
    data = load_data()
    if not data:
        print(f"{COLOR_INFO}No services found.{COLOR_RESET}")
        return
    print(f"{COLOR_INFO}Available services:{COLOR_RESET}")
    for name in data.keys():
        print(f"{COLOR_SUCCESS}- {name}{COLOR_RESET}")
    name = input("Service name to retrieve: ")
    if name in data:
        # use the new function to prompt and verify master password
        master_password = get_master_password(data, "PASSWORD")
        key_hash = custom_sha256(master_password)
        try:
            decrypted_password = custom_decrypt(data[name]["PASSWORD"], key_hash)
        except Exception as e:
            print(f"{COLOR_INFO}Failed to decrypt. Possibly wrong master password.{COLOR_RESET}")
            return
        print(f"{COLOR_SUCCESS}Username: {data[name]['USERNAME']}{COLOR_RESET}")
        print(f"{COLOR_SUCCESS}Password: {decrypted_password}{COLOR_RESET}")
    else:
        print(f"{COLOR_INFO}Service not found.{COLOR_RESET}")

def gen_pw(length):
    import random
    import string
    length = int(length)
    password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    print(f"{COLOR_SUCCESS}Generated password: {password}{COLOR_RESET}")

if __name__ == "__main__":
    load_data()  # Ensure the database is created if it does not exist
    if len(sys.argv) > 1:
        if sys.argv[1] == "add":
            add_entry()
        elif sys.argv[1] == "delete":
            delete_entry()
        elif sys.argv[1] == "modify":
            modify_entry()
        elif sys.argv[1] == "get":
            retrieve_entry()
        elif sys.argv[1] == "gen":
            if len(sys.argv) > 2:
                gen_pw(sys.argv[2])
            else:
                print(f"{COLOR_INFO}No length is given{COLOR_RESET}")
