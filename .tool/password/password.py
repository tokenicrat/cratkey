import json
import os
import sys
import random
import string
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Platform-specific imports
IS_WINDOWS = os.name == 'nt'

if IS_WINDOWS:
    import msvcrt
else:
    import termios
    import tty

# File storage
PASSWORD_FILE = ".data/password/key.json"

# Terminal UI constants
COLOR_ERROR = "\033[91m"
COLOR_INFO = "\033[96m"
COLOR_HEADER = "\033[94m"
COLOR_SUCCESS = "\033[92m"
COLOR_RESET = "\033[0m"

# UI elements
HEADER_STYLE = "═"
HEADER_PREFIX = "┌"
HEADER_SUFFIX = "┐"
FOOTER_PREFIX = "└"
FOOTER_SUFFIX = "┘"
SEPARATOR = "─"

def print_header(title):
    print(f"\n**** {COLOR_INFO}{title}{COLOR_RESET} ****\n")

def print_error(message):
    """Print an error message."""
    print(f"{COLOR_ERROR}Error: {message}{COLOR_RESET}")

def print_info(message):
    """Print an info message."""
    print(f"{COLOR_INFO}{message}{COLOR_RESET}")

def print_success(message):
    """Print a success message."""
    print(f"{COLOR_SUCCESS}{message}{COLOR_RESET}")

def custom_getpass(prompt="Password: "):
    """Securely get a password from the user without echoing it to the terminal."""
    print(prompt, end='', flush=True)
    password = ""

    if IS_WINDOWS:
        # Windows implementation
        while True:
            ch = msvcrt.getch()
            ch = ch.decode('utf-8', errors='replace')
            if ch == '\r' or ch == '\n':  # Enter
                break
            elif ch == '\b':  # Backspace
                if password:
                    password = password[:-1]
                    msvcrt.putch(b'\b')
                    msvcrt.putch(b' ')
                    msvcrt.putch(b'\b')
            elif ch.isprintable():
                password += ch
                msvcrt.putch(b'*')
        print()
    else:
        # Unix/Linux/MacOS implementation
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch == '\n' or ch == '\r':
                    break
                elif ch == '\x7f':  # Backspace
                    if password:
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
    """Generate SHA-256 hash of the provided string."""
    return sha256(data.encode()).digest()

def custom_base64_encode(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode()

def custom_base64_decode(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data)

def custom_encrypt(data: str, key: bytes) -> str:
    """Encrypt data using AES-CBC with the provided key."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data.encode(), AES.block_size))
    return custom_base64_encode(encrypted_data)

def custom_decrypt(data: str, key: bytes) -> str:
    """Decrypt data using AES-CBC with the provided key."""
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
        print_header("Create Master Password")
        while True:
            pw1 = custom_getpass("Create new master password: ")
            pw2 = custom_getpass("Retype master password: ")
            if pw1 == "" or pw1 != pw2:
                print_error("Passwords do not match or cannot be empty. Try again.")
            else:
                print_success("Master password created successfully!")
                return pw1
    else:
        print_header("Enter Master Password")
        while True:
            master_password = custom_getpass("Master password: ")
            key_hash = custom_sha256(master_password)
            sample_entry = next(iter(data.values()))
            try:
                # Try decrypting to verify the password
                custom_decrypt(sample_entry[field], key_hash)
                return master_password
            except Exception:
                print_error("Master password incorrect. Please try again.")

def load_data():
    """Load password data from file, creating it if it doesn't exist."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(PASSWORD_FILE), exist_ok=True)

    if not os.path.exists(PASSWORD_FILE):
        save_data({})
    try:
        with open(PASSWORD_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        save_data({})
        return {}

def save_data(data):
    """Save password data to file."""
    with open(PASSWORD_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_entry():
    """Add a new password entry."""
    print_header("Add New Password Entry")
    data = load_data()
    name = input("Service name: ")

    # Check if service already exists
    if name in data:
        print_error(f"Service '{name}' already exists. Use 'modify' to update it.")
        return

    username = input("Username: ")
    password = input("Password (leave empty to generate): ")

    if not password:
        length = input("Password length (default 12): ") or "12"
        try:
            password = gen_pw(length, return_password=True)
            print_success(f"Generated password: {password}")
        except ValueError:
            print_error("Invalid password length. Using default length of 12.")
            password = gen_pw("12", return_password=True)
            print_success(f"Generated password: {password}")

    # Get master password
    master_password = get_master_password(data, "PASSWORD")
    key_hash = custom_sha256(master_password)

    # Save the entry
    data[name] = {"USERNAME": username, "PASSWORD": custom_encrypt(password, key_hash)}
    save_data(data)
    print_success(f"Entry for '{name}' added successfully!")

def delete_entry():
    """Delete an existing password entry."""
    print_header("Delete Password Entry")
    data = load_data()

    if not data:
        print_info("No services found.")
        return

    print_info("Available services:")
    for i, name in enumerate(data.keys(), 1):
        print(f"{COLOR_SUCCESS}{i}. {name}{COLOR_RESET}")

    name = input("Service name to delete: ")
    if name in data:
        confirmation = input(f"Are you sure you want to delete '{name}'? (y/n): ")
        if confirmation.lower() == 'y':
            del data[name]
            save_data(data)
            print_success(f"Entry for '{name}' deleted successfully!")
        else:
            print_info("Deletion cancelled.")
    else:
        print_error(f"Service '{name}' not found.")

def modify_entry():
    """Modify an existing password entry."""
    print_header("Modify Password Entry")
    data = load_data()

    if not data:
        print_info("No services found.")
        return

    print_info("Available services:")
    for i, name in enumerate(data.keys(), 1):
        print(f"{COLOR_SUCCESS}{i}. {name}{COLOR_RESET}")

    name = input("Service name to modify: ")
    if name in data:
        # Get master password to decrypt
        master_password = get_master_password(data, "PASSWORD")
        key_hash = custom_sha256(master_password)

        try:
            username = data[name]["USERNAME"]
            decrypted_password = custom_decrypt(data[name]["PASSWORD"], key_hash)

            print_info(f"Current username: {username}")
            new_username = input("New username (leave empty to keep current): ") or username

            print_info(f"Current password: {decrypted_password}")
            new_password = input("New password (leave empty to keep current or 'gen' to generate): ")

            if new_password.lower() == 'gen':
                length = input("Password length (default 12): ") or "12"
                try:
                    new_password = gen_pw(length, return_password=True)
                    print_success(f"Generated password: {new_password}")
                except ValueError:
                    print_error("Invalid password length. Using default length of 12.")
                    new_password = gen_pw("12", return_password=True)
                    print_success(f"Generated password: {new_password}")
            elif not new_password:
                new_password = decrypted_password

            # Save the modified entry
            data[name] = {"USERNAME": new_username, "PASSWORD": custom_encrypt(new_password, key_hash)}
            save_data(data)
            print_success(f"Entry for '{name}' modified successfully!")

        except Exception as e:
            print_error(f"Failed to modify entry: {str(e)}")
    else:
        print_error(f"Service '{name}' not found.")

def view_entry():
    """View a password entry."""
    print_header("View Password Entry")
    data = load_data()

    if not data:
        print_info("No services found.")
        return

    print_info("Available services:")
    for i, name in enumerate(data.keys(), 1):
        print(f"{COLOR_SUCCESS}{i}. {name}{COLOR_RESET}")

    name = input("Service name to view: ")
    if name in data:
        # Get master password to decrypt
        master_password = get_master_password(data, "PASSWORD")
        key_hash = custom_sha256(master_password)

        try:
            username = data[name]["USERNAME"]
            decrypted_password = custom_decrypt(data[name]["PASSWORD"], key_hash)

            print()
            print(f"{COLOR_HEADER}{'Service:'.ljust(12)}{COLOR_RESET} {COLOR_SUCCESS}{name}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Username:'.ljust(12)}{COLOR_RESET} {COLOR_SUCCESS}{username}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Password:'.ljust(12)}{COLOR_RESET} {COLOR_SUCCESS}{decrypted_password}{COLOR_RESET}")
            print()

            input("Press Enter to continue...")

        except Exception as e:
            print_error(f"Failed to decrypt: {str(e)}")
    else:
        print_error(f"Service '{name}' not found.")

def gen_pw(length, return_password=False):
    """Generate a secure random password."""
    try:
        length = int(length)
        if length <= 0:
            raise ValueError("Length must be positive")

        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

        if return_password:
            return password
        else:
            print_success(f"Generated password: {password}")

    except ValueError:
        if not return_password:
            print_error("Invalid password length. Please provide a positive integer.")
        else:
            raise ValueError("Invalid password length")

def print_usage():
    """Print usage information."""
    print_header("Password Manager")
    print("Usage: python password_manager.py [COMMAND]")
    print()
    print("Commands:")
    print("  add      Add a new password entry")
    print("  view     View an existing password entry")
    print("  modify   Modify an existing password entry")
    print("  delete   Delete an existing password entry")
    print("  gen      Generate a random password")
    print()

if __name__ == "__main__":
    try:
        # Ensure the database is created if it does not exist
        load_data()

        if len(sys.argv) > 1:
            if sys.argv[1] == "add":
                add_entry()
            elif sys.argv[1] == "delete":
                delete_entry()
            elif sys.argv[1] == "modify":
                modify_entry()
            elif sys.argv[1] == "view":
                view_entry()
            elif sys.argv[1] == "gen":
                if len(sys.argv) > 2:
                    gen_pw(sys.argv[2])
                else:
                    print_error("No length provided. Usage: python password_manager.py gen [LENGTH]")
            else:
                print_error(f"Unknown command: {sys.argv[1]}")
                print_usage()
        else:
            print_error("No command provided")
            print_usage()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
        # For debugging purposes, uncomment the line below
        # import traceback; traceback.print_exc()
