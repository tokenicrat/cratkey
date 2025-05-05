import json
import os
import sys
import time
import pyotp
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
    import select

# File storage
TOTP_FILE = ".data/totp/key.json"

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
    """Load TOTP data from file, creating it if it doesn't exist."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(TOTP_FILE), exist_ok=True)

    if not os.path.exists(TOTP_FILE):
        save_data({})
    try:
        with open(TOTP_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        save_data({})
        return {}

def save_data(data):
    """Save TOTP data to file."""
    with open(TOTP_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_entry():
    """Add a new TOTP entry."""
    print_header("Add New TOTP Entry")
    data = load_data()
    name = input("Service name: ")

    # Check if service already exists
    if name in data:
        print_error(f"Service '{name}' already exists. Use 'modify' to update it.")
        return

    key = input("TOTP secret key: ")
    if not key:
        print_error("TOTP secret key cannot be empty.")
        return

    digit = input("Digits (default 6): ") or "6"
    period = input("Period (default 30s): ") or "30"

    try:
        # Validate inputs
        int(digit)
        int(period)
    except ValueError:
        print_error("Digits and period must be valid integers.")
        return

    # Get master password
    master_password = get_master_password(data, "KEY")
    key_hash = custom_sha256(master_password)

    # Save the entry
    data[name] = {"KEY": custom_encrypt(key, key_hash), "DIGIT": digit, "PERIOD": period}
    save_data(data)
    print_success(f"Entry for '{name}' added successfully!")

def delete_entry():
    """Delete an existing TOTP entry."""
    print_header("Delete TOTP Entry")
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
    """Modify an existing TOTP entry."""
    print_header("Modify TOTP Entry")
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
        master_password = get_master_password(data, "KEY")
        key_hash = custom_sha256(master_password)

        try:
            decrypted_key = custom_decrypt(data[name]["KEY"], key_hash)
            digit = data[name]["DIGIT"]
            period = data[name]["PERIOD"]

            print_info(f"Current TOTP key: {decrypted_key}")
            new_key = input("New TOTP key (leave empty to keep current): ") or decrypted_key

            print_info(f"Current digits: {digit}")
            new_digit = input("New digits (leave empty to keep current): ") or digit

            print_info(f"Current period: {period}")
            new_period = input("New period (leave empty to keep current): ") or period

            try:
                # Validate inputs
                int(new_digit)
                int(new_period)
            except ValueError:
                print_error("Digits and period must be valid integers.")
                return

            # Save the modified entry
            data[name] = {"KEY": custom_encrypt(new_key, key_hash), "DIGIT": new_digit, "PERIOD": new_period}
            save_data(data)
            print_success(f"Entry for '{name}' modified successfully!")

        except Exception as e:
            print_error(f"Failed to modify entry: {str(e)}")
    else:
        print_error(f"Service '{name}' not found.")

def view_entry():
    """View a TOTP entry and its current code."""
    print_header("View TOTP Entry")
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
        master_password = get_master_password(data, "KEY")
        key_hash = custom_sha256(master_password)

        try:
            decrypted_key = custom_decrypt(data[name]["KEY"], key_hash)
            digits = int(data[name]["DIGIT"])
            period = int(data[name]["PERIOD"])

            totp = pyotp.TOTP(decrypted_key, digits=digits, interval=period)
            code = totp.now()
            expires_in = int(period - (time.time() % period))

            print()
            print(f"{COLOR_HEADER}{'Service:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{name}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'TOTP Key:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{decrypted_key}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Digits:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{digits}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Period:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{period}s{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Current Code:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{code}{COLOR_RESET}")
            print(f"{COLOR_HEADER}{'Expires in:'.ljust(15)}{COLOR_RESET} {COLOR_SUCCESS}{expires_in}s{COLOR_RESET}")
            print()

            input("Press Enter to continue...")

        except Exception as e:
            print_error(f"Failed to decrypt: {str(e)}")
    else:
        print_error(f"Service '{name}' not found.")

def is_key_pressed():
    """Check if a key is pressed in a platform-independent way."""
    if IS_WINDOWS:
        return msvcrt.kbhit()
    else:
        return select.select([sys.stdin], [], [], 0)[0]

def read_key():
    """Read a key press in a platform-independent way."""
    if IS_WINDOWS:
        return msvcrt.getch().decode('utf-8', errors='replace').lower()
    else:
        return sys.stdin.read(1).lower()

def generate_totp():
    """Generate TOTP codes for all services in real-time."""
    data = load_data()
    if not data:
        print_error("No TOTP services found. Add one first using 'add' command.")
        return

    # Prompt and verify master password using the "KEY" field
    master_password = get_master_password(data, "KEY")
    key_hash = custom_sha256(master_password)

    # Set up terminal for real-time input
    if not IS_WINDOWS:
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
        except:
            pass  # Skip if not supported

    try:
        while True:
            os.system('cls' if IS_WINDOWS else 'clear')
            print_header("TOTP Codes")
            print_info("Press 'q' to exit")

            # Create table header
            print(f"{COLOR_HEADER}┌{'─' * 19}┬{'─' * 12}┬{'─' * 12}┐{COLOR_RESET}")
            print(f"{COLOR_HEADER}│ {'Service'.ljust(17)} │ {'TOTP Code'.ljust(10)} │ {'Expires in'.ljust(10)} │{COLOR_RESET}")
            print(f"{COLOR_HEADER}├{'─' * 19}┼{'─' * 12}┼{'─' * 12}┤{COLOR_RESET}")

            # Create table rows
            for name, details in data.items():
                try:
                    decrypted_key = custom_decrypt(details["KEY"], key_hash)
                except Exception:
                    print(f"{COLOR_ERROR}│ {name.ljust(17)} │ {'ERROR'.ljust(10)} │ {'ERROR'.ljust(10)} │{COLOR_RESET}")
                    continue

                totp = pyotp.TOTP(decrypted_key, digits=int(details["DIGIT"]), interval=int(details["PERIOD"]))
                code = totp.now()
                expires_in = str(int(totp.interval - (time.time() % totp.interval))) + "s"

                print(f"{COLOR_SUCCESS}│ {name.ljust(17)} │ {code.ljust(10)} │ {expires_in.ljust(10)} │{COLOR_RESET}")

            # Create table footer
            print(f"{COLOR_HEADER}└{'─' * 19}┴{'─' * 12}┴{'─' * 12}┘{COLOR_RESET}")

            time.sleep(1)
            if is_key_pressed():
                if read_key() == 'q':
                    break

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
    finally:
        # Restore terminal settings if needed
        if not IS_WINDOWS:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                pass  # Skip if not supported

def print_usage():
    """Print usage information."""
    print_header("TOTP Manager")
    print("Usage: python totp_manager.py [COMMAND]")
    print()
    print("Commands:")
    print("  add        Add a new TOTP entry")
    print("  view       View an existing TOTP entry and its current code")
    print("  modify     Modify an existing TOTP entry")
    print("  delete     Delete an existing TOTP entry")
    print("  generate   Generate TOTP codes for all services in real-time")
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
            elif sys.argv[1] == "generate":
                generate_totp()
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
