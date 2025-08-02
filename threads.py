from PyQt6.QtCore import QThread, pyqtSignal

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

import os
import psutil
import string
import random
import hashlib
import tarfile


def get_optimal_block_size():
    """Determine the optimal block size for encryption/decryption based on available RAM.

    Returns:
        int: Optimal block size in bytes based on system RAM.
    """
    try:
        available_ram = psutil.virtual_memory().available
        gb_ram = available_ram // (1024 ** 3)

        if gb_ram <= 1:    return 65536    # 64 KiB block size
        elif gb_ram <= 2:  return 131072   # 128 KiB block size
        elif gb_ram <= 3:  return 262144   # 256 KiB block size
        elif gb_ram <= 4:  return 524288   # 512 KiB block size
        elif gb_ram <= 6:  return 524288   # 512 KiB block size
        elif gb_ram <= 8:  return 1048576  # 1 MiB block size
        elif gb_ram <= 12: return 1048576  # 1 MiB block size
        elif gb_ram <= 16: return 1572864  # 1.5 MiB block size
        elif gb_ram <= 24: return 1572864  # 1.5 MiB block size
        elif gb_ram <= 32: return 3145728  # 3 MiB block size
        elif gb_ram >= 32: return 3145728  # 3 MiB block size
    except:
        return 524288  # 512 KiB block size as fallback


def generate_unique_file_name(file_path, add_extension=".pack"):
    """Generate a unique file name by appending an extension or adding a counter if needed.

    Args:
        file_path (str): Original file path
        add_extension (str): Extension to append (default: ".pack")

    Returns:
        str: Unique file path with the specified extension
    """
    if os.path.isfile(file_path) and not os.path.exists(f"{file_path}{add_extension}"):
        return f"{file_path}{add_extension}"
    elif os.path.isfile(file_path) and os.path.exists(f"{file_path}{add_extension}"):
        file_directory = os.path.dirname(file_path)
        base_name, extension = os.path.splitext(os.path.basename(file_path))
        unique_name = base_name
        counter = 1

        while os.path.exists(os.path.join(file_directory, f"{unique_name} ({counter}){extension}{add_extension}")):
            counter += 1

        if extension:
            return os.path.join(file_directory, f"{unique_name} ({counter}){extension}{add_extension}")
        else:
            return os.path.join(file_directory, f"{unique_name} ({counter}){add_extension}")

    elif os.path.isdir(file_path) and not os.path.exists(os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")):
        return os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")
    elif os.path.isdir(file_path) and os.path.exists(os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")):
        base_folder_name = os.path.basename(os.path.normpath(file_path))
        unique_folder_name = base_folder_name
        counter = 1

        while os.path.exists(os.path.join(file_path, unique_folder_name + add_extension)):
            unique_folder_name = f"{base_folder_name} ({counter})"
            counter += 1

        return os.path.join(file_path, unique_folder_name + add_extension)


def generate_unique_key_file_name(file_path, add_extension=".key"):
    """Generate a unique key file name by appending an extension or adding a counter if needed.

    Args:
        file_path (str): Original file path
        add_extension (str): Extension to append (default: ".key")

    Returns:
        str: Unique key file path with the specified extension
    """
    if not os.path.exists(f"{file_path}_{add_extension}"):
        return f"{file_path}_{add_extension}"
    elif os.path.exists(f"{file_path}_{add_extension}"):
        base_name, extension = os.path.splitext(os.path.basename(file_path))
        counter = 1

        while os.path.exists(os.path.join(f"{base_name}_{counter}{extension}{add_extension}")):
            counter += 1

        if extension:
            return os.path.join(f"{base_name}_{counter}{extension}{add_extension}")
        else:
            return os.path.join(f"{base_name}_{counter}{add_extension}")


def generate_random_string(length):
    """Generate a random alphanumeric string of specified length.

    Args:
        length (int): Length of the string to generate

    Returns:
        str: Random alphanumeric string
    """
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


class EncryptionThread(QThread):
    """Thread for handling file encryption operations.

    Signals:
        progress_updated (int): Emits progress percentage
        operation_completed (str, str): Emits success message title and text
        error_occurred (str, str): Emits error title and message
    """
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str, str)

    def __init__(self, parent=None):
        """Initialize the encryption thread."""
        super().__init__(parent)
        self.file_path = ""
        self.password = ""
        self.separate_iv_key = False
        self.recovery_key = False
        self.remove_encrypted_files = False
        self.show_progress = True
        self.compressed_files = []

    def setup(self, file_path, password, separate_iv_key, recovery_key, remove_encrypted_files, show_progress):
        """Configure the encryption thread parameters.

        Args:
            file_path (str): Path to file/folder to encrypt
            password (str): Encryption password
            separate_iv_key (bool): Whether to store IV separately
            recovery_key (bool): Whether to generate recovery key
            remove_encrypted_files (bool): Whether to delete original files
            show_progress (bool): Whether to emit progress updates
        """
        self.file_path = file_path
        self.password = password
        self.separate_iv_key = separate_iv_key
        self.recovery_key = recovery_key
        self.remove_encrypted_files = remove_encrypted_files
        self.show_progress = show_progress

    def run(self):
        """Execute the encryption process."""
        try:
            # Generate encryption parameters
            iv = get_random_bytes(16)
            iv_hash = hashlib.sha1(iv).digest()
            key = hashlib.sha256(self.password.encode()).digest()
            block_size = get_optimal_block_size()

            # Determine file paths and names
            if os.path.isdir(self.file_path):
                compressed_file_path = generate_unique_file_name(self.file_path, add_extension=".temp")
                self.compressed_files = self.compress_directory(self.file_path, compressed_file_path)
                encrypted_file_path = generate_unique_file_name(self.file_path)
                file_to_encrypt = compressed_file_path
            else:
                encrypted_file_path = generate_unique_file_name(self.file_path)
                file_to_encrypt = self.file_path

            # Create encrypted file
            with open(encrypted_file_path, "wb") as encrypted_file:
                file_size = os.path.getsize(file_to_encrypt)
                total_tasks = file_size
                completed_tasks = 0

                # Write IV to file or separate key
                if not self.separate_iv_key:
                    encrypted_file.write(iv)
                else:
                    iv_key_file = f"{file_to_encrypt}.ivkey" if not os.path.exists(f"{file_to_encrypt}.ivkey") \
                        else generate_unique_key_file_name(file_to_encrypt, add_extension=".ivkey")
                    with open(iv_key_file, "wb") as key_file:
                        key_file.write(iv)

                # Encrypt the file
                with open(file_to_encrypt, "rb") as file:
                    cipher = AES.new(key, AES.MODE_EAX, iv)
                    while True:
                        chunk = file.read(block_size)
                        if not chunk:
                            break
                        encrypted_chunk = cipher.encrypt(chunk)
                        encrypted_file.write(encrypted_chunk)
                        completed_tasks += len(chunk)
                        completed_percent = (completed_tasks / total_tasks) * 100
                        if self.show_progress:
                            self.progress_updated.emit(int(completed_percent))

                # Write IV hash
                encrypted_file.write(iv_hash)

                # Remove original files if requested
                if self.remove_encrypted_files:
                    if os.path.isfile(self.file_path):
                        os.remove(self.file_path)
                    elif os.path.isdir(self.file_path):
                        for file in self.compressed_files:
                            os.remove(file)
                        for root, dirs, files in os.walk(self.file_path, topdown=False):
                            for dir in dirs:
                                dir_path = os.path.join(root, dir)
                                if not os.listdir(dir_path):
                                    os.rmdir(dir_path)

            # Generate recovery key if needed
            if self.recovery_key:
                keyfile = generate_unique_key_file_name(file_to_encrypt, add_extension=".rkey")
                hashkey = hashlib.sha256(self.password.encode()).hexdigest()
                with open(keyfile, "w") as file:
                    file.write(hashkey)

            # Clean up temporary files
            if os.path.isdir(self.file_path):
                os.remove(compressed_file_path)

            self.operation_completed.emit("Encryption Successful", "Encryption process completed successfully.")

        except Exception as e:
            self.error_occurred.emit("Unhandled Exception Error", f"An error occurred during encryption: {str(e)}")

    def compress_directory(self, folder_path, compressed_file_path):
        """Compress a directory into a tar file for encryption.

        Args:
            folder_path (str): Path to folder to compress
            compressed_file_path (str): Destination path for compressed file

        Returns:
            list: List of files that were successfully compressed
        """
        compressed_files = []
        failed_list = []

        empty_file_path = os.path.join(folder_path, "~encrypto_pack")
        with open(empty_file_path, "w") as file:
            file.write("encrypto_packed_this_tar_file")

        with tarfile.open(compressed_file_path, 'w') as compressed_file:
            for root, dirs, files in os.walk(folder_path):
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    relative_path = os.path.relpath(dir_path, folder_path)
                    compressed_file.add(dir_path, arcname=relative_path)

                for file in files:
                    file_path = os.path.join(root, file)

                    if file_path == os.path.abspath(__file__) or file_path == compressed_file_path:
                        continue

                    try:
                        relative_path = os.path.relpath(file_path, folder_path)
                        compressed_file.add(file_path, arcname=relative_path)
                        compressed_files.append(file_path)
                    except Exception as e:
                        failed_list.append(file_path)

        os.remove(empty_file_path)

        if not compressed_files:
            os.remove(compressed_file_path)
            self.error_occurred.emit("Error info", "No files were successfully encrypted, this could be due to permission error.")
            return []

        if failed_list:
            self.error_occurred.emit("Warning", f"Failed to access file(s):\n\n{', '.join(failed_list)}")

        return compressed_files


class DecryptionThread(QThread):
    """Thread for handling file decryption operations.

    Signals:
        progress_updated (int): Emits progress percentage
        operation_completed (str, str): Emits success message title and text
        error_occurred (str, str): Emits error title and message
    """
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str, str)

    def __init__(self, parent=None):
        """Initialize the decryption thread."""
        super().__init__(parent)
        self.file_path = ""
        self.password = ""
        self.recovery_key_file = ""
        self.iv_key_file = ""
        self.remove_encrypted_files = False
        self.show_progress = True
        self.hash_password = True
        self.separate_iv_key = None

    def setup(self, file_path, password, recovery_key_file, iv_key_file, 
              remove_encrypted_files, show_progress, hash_password, separate_iv_key):
        """Configure the decryption thread parameters.

        Args:
            file_path (str): Path to file/folder to decrypt
            password (str): Decryption password
            recovery_key_file (str): Path to recovery key file
            iv_key_file (str): Path to IV key file
            remove_encrypted_files (bool): Whether to delete encrypted files after
            show_progress (bool): Whether to emit progress updates
            hash_password (bool): Whether password needs hashing
            separate_iv_key (str): Path to separate IV key file if used
        """
        self.file_path = file_path
        self.password = password
        self.recovery_key_file = recovery_key_file
        self.iv_key_file = iv_key_file
        self.remove_encrypted_files = remove_encrypted_files
        self.show_progress = show_progress
        self.hash_password = hash_password
        self.separate_iv_key = separate_iv_key

    def run(self):
        """Execute the decryption process."""
        try:
            # Set up decryption parameters
            block_size = get_optimal_block_size()

            if self.hash_password:
                key = hashlib.sha256(self.password.encode()).digest()
            else:
                key = bytes.fromhex(self.password)

            # Determine file to decrypt
            if os.path.isdir(self.file_path):
                file_name = os.path.basename(self.file_path)
                file_to_decrypt = os.path.join(self.file_path, file_name + ".pack")
            elif os.path.isfile(self.file_path):
                file_to_decrypt = self.file_path
            else:
                self.error_occurred.emit("ValueError", "An error occurred during decryption: Invalid file or folder name.")
                return

            # Read IV and IV hash
            if self.separate_iv_key is None:
                if os.path.getsize(file_to_decrypt) < 36:
                    self.error_occurred.emit("ValueError", "Encrypted file size must be higher than 36 bytes.")
                    return
                with open(file_to_decrypt, "rb") as file:
                    iv = file.read(16)
                    file.seek(-20, os.SEEK_END)
                    expected_iv_hash = file.read()
            else:
                if not os.path.exists(self.separate_iv_key):
                    self.error_occurred.emit("ValueError", "Invalid key file path.")
                    return
                if os.path.getsize(self.separate_iv_key) < 16:
                    self.error_occurred.emit("ValueError", "Invalid or corrupted key file.")
                    return
                with open(self.separate_iv_key, "rb") as ivkey_file:
                    iv = ivkey_file.read(16)
                with open(file_to_decrypt, "rb") as file:
                    file.seek(-20, os.SEEK_END)
                    expected_iv_hash = file.read()

            # Verify IV hash
            iv_hash = hashlib.sha1(iv).digest()
            if iv_hash != expected_iv_hash:
                self.error_occurred.emit("File Error", "IV key mismatch - file corrupted or wrong/missing IV-key file (required for decryption if generated)")
                return

            # Create extraction directory
            encrypted_file_dir = os.path.dirname(file_to_decrypt)
            base_file_name = os.path.basename(file_to_decrypt)
            if base_file_name.endswith(".pack"):
                base_file_name = os.path.splitext(os.path.basename(base_file_name))[0]
            extraction_dir = os.path.join(encrypted_file_dir, base_file_name + "_unpacked")

            counter = 1
            while os.path.exists(extraction_dir):
                extraction_dir = os.path.join(encrypted_file_dir, base_file_name + "_unpacked;" + generate_random_string(5))
                counter += 1
            os.makedirs(extraction_dir)

            if file_to_decrypt.endswith(".pack"):
                decrypted_file_name = os.path.splitext(os.path.basename(file_to_decrypt))[0]
            else:
                decrypted_file_name = file_to_decrypt

            decrypted_file_path = os.path.join(extraction_dir, decrypted_file_name)

            # Decrypt file
            with open(decrypted_file_path, "wb") as decrypted_file:
                if self.separate_iv_key is None:
                    file_size = os.path.getsize(file_to_decrypt) - 36
                else:
                    file_size = os.path.getsize(file_to_decrypt) - 20

                total_tasks = file_size
                completed_tasks = 0

                with open(file_to_decrypt, "rb") as file:
                    if self.separate_iv_key is None:
                        file.seek(16)
                    encrypted_data = file.read()[:-20]
                    cipher = AES.new(key, AES.MODE_EAX, iv)

                    offset = 0
                    while offset < len(encrypted_data):
                        chunk = encrypted_data[offset:offset + block_size]
                        decrypted_chunk = cipher.decrypt(chunk)
                        decrypted_file.write(decrypted_chunk)
                        offset += block_size
                        completed_tasks += len(decrypted_chunk)
                        completed_percent = (completed_tasks / total_tasks) * 100
                        if self.show_progress:
                            self.progress_updated.emit(int(completed_percent))

            # Extract if it's a tar file
            if tarfile.is_tarfile(decrypted_file_path):
                with tarfile.open(decrypted_file_path, "r") as tar_ref:
                    files_list = [member.name for member in tar_ref.getmembers() if not member.isdir()]

                if "~encrypto_pack" in files_list:
                    with tarfile.open(decrypted_file_path, "r") as tar_ref:
                        tar_ref.extractall(extraction_dir)
                    os.remove(os.path.join(extraction_dir, "~encrypto_pack"))
                    os.remove(decrypted_file_path)

            # Remove encrypted file if requested
            if self.remove_encrypted_files:
                os.remove(file_to_decrypt)

            self.operation_completed.emit("Decryption Successful", "Decryption process completed successfully.")

        except Exception as e:
            self.error_occurred.emit("Unhandled Exception Error", f"An error occurred during decryption: {str(e)}")

