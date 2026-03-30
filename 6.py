#!/usr/bin/env python3

# Script: Symmetric Key File Encryption Tool
# Purpose: Encrypt and decrypt files in a directory

from cryptography.fernet import Fernet
import os
import sys
import hashlib
from datetime import datetime


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'


def generate_key(key_file='encryption.key'):
    try:
        key = Fernet.generate_key()

        with open(key_file, 'wb') as f:
            f.write(key)

        os.chmod(key_file, 0o600)

        print(f"{Colors.GREEN}[✓] Encryption key generated: {key_file}{Colors.END}")
        return key

    except Exception as e:
        print(f"{Colors.RED}[✗] Error generating key: {e}{Colors.END}")
        return None


def load_key(key_file='encryption.key'):
    try:
        if not os.path.exists(key_file):
            print(f"{Colors.YELLOW}[!] Key file not found: {key_file}{Colors.END}")
            return None

        with open(key_file, 'rb') as f:
            key = f.read()

        if len(key) != 44:
            print(f"{Colors.RED}[✗] Invalid key format{Colors.END}")
            return None

        print(f"{Colors.GREEN}[✓] Key loaded successfully{Colors.END}")
        return key

    except Exception as e:
        print(f"{Colors.RED}[✗] Error loading key: {e}{Colors.END}")
        return None


def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def encrypt_file(file_path, key):
    try:
        cipher = Fernet(key)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        original_hash = calculate_hash(file_path)

        encrypted_data = cipher.encrypt(file_data)

        encrypted_file = file_path + '.enc'
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)

        metadata_file = file_path + '.meta'
        with open(metadata_file, 'w') as f:
            f.write(f"{original_hash}\n")
            f.write(f"{len(file_data)}\n")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.GREEN}[✓] Encrypted: {file_path} ({len(file_data)} bytes){Colors.END}")

        return True

    except Exception as e:
        print(f"{Colors.RED}[✗] Error encrypting {file_path}: {e}{Colors.END}")
        return False


def decrypt_file(encrypted_file, key):
    try:
        cipher = Fernet(key)

        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        original_file = encrypted_file.replace('.enc', '')

        metadata_file = encrypted_file.replace('.enc', '.meta')

        if os.path.exists(metadata_file):
            with open(metadata_file, 'r') as f:
                lines = f.readlines()
                stored_hash = lines[0].strip()
                stored_size = int(lines[1].strip())

            if len(decrypted_data) != stored_size:
                print(f"{Colors.RED}[✗] Size mismatch in {encrypted_file}{Colors.END}")
                return False

            decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
            if decrypted_hash != stored_hash:
                print(f"{Colors.RED}[✗] Hash mismatch in {encrypted_file}{Colors.END}")
                return False

        with open(original_file, 'wb') as f:
            f.write(decrypted_data)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.GREEN}[✓] Decrypted: {original_file} ({len(decrypted_data)} bytes){Colors.END}")

        return True

    except Exception as e:
        print(f"{Colors.RED}[✗] Error decrypting {encrypted_file}: {e}{Colors.END}")
        return False


def encrypt_directory(directory, key):
    encrypted_count = 0
    failed_count = 0

    if not os.path.isdir(directory):
        print(f"{Colors.RED}[✗] Directory not found: {directory}{Colors.END}")
        return 0, 0

    print(f"{Colors.BLUE}[*] Starting encryption of directory: {directory}{Colors.END}")

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.key') or file.endswith('.meta') or file.endswith('.enc'):
                continue

            file_path = os.path.join(root, file)

            if encrypt_file(file_path, key):
                encrypted_count += 1
            else:
                failed_count += 1

    return encrypted_count, failed_count


def decrypt_directory(directory, key):
    decrypted_count = 0
    failed_count = 0

    if not os.path.isdir(directory):
        print(f"{Colors.RED}[✗] Directory not found: {directory}{Colors.END}")
        return 0, 0

    print(f"{Colors.BLUE}[*] Starting decryption of directory: {directory}{Colors.END}")

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)

                if decrypt_file(file_path, key):
                    decrypted_count += 1
                else:
                    failed_count += 1

    return decrypted_count, failed_count


if __name__ == "__main__":

    print("""
╔═══════════════════════════════════════════════════════╗
║    Symmetric Key File Encryption Tool                 ║
║    Using Fernet (AES-128 + HMAC)                      ║
╚═══════════════════════════════════════════════════════╝
""")

    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <encrypt|decrypt> <directory> [key_file]")
        sys.exit(1)

    operation = sys.argv[1].lower()
    directory = sys.argv[2] if len(sys.argv) > 2 else '.'
    key_file = sys.argv[3] if len(sys.argv) > 3 else 'encryption.key'

    if operation not in ['encrypt', 'decrypt']:
        print(f"{Colors.RED}Invalid operation. Use 'encrypt' or 'decrypt'{Colors.END}")
        sys.exit(1)

    try:
        if operation == 'encrypt':

            if not os.path.exists(key_file):
                print(f"{Colors.YELLOW}[!] Key file not found. Generating new key...{Colors.END}")
                key = generate_key(key_file)
            else:
                key = load_key(key_file)

            if key is None:
                sys.exit(1)

            encrypted, failed = encrypt_directory(directory, key)

            print(f"{Colors.BLUE}[*] Encryption Summary:{Colors.END}")
            print(f"Files encrypted: {encrypted}")
            print(f"Files failed: {failed}")
            print(f"Key file: {key_file}")

        elif operation == 'decrypt':

            key = load_key(key_file)

            if key is None:
                print(f"{Colors.RED}[✗] Cannot decrypt without key file{Colors.END}")
                sys.exit(1)

            decrypted, failed = decrypt_directory(directory, key)

            print(f"{Colors.BLUE}[*] Decryption Summary:{Colors.END}")
            print(f"Files decrypted: {decrypted}")
            print(f"Files failed: {failed}")

    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user{Colors.END}")
        sys.exit(0)

    except Exception as e:
        print(f"{Colors.RED}[✗] Unexpected error: {e}{Colors.END}")
        sys.exit(1)