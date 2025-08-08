from constants import (
    APP_NAME,
    FILE_HEADER,
    PASS_TEXT,
    EOF_MARKER,
    CURRENT_EXT,
    IV_KEY_EXT,
    RECOVERY_KEY_EXT,
    TEMP_EXT,
    MARKER_FILE,
    MARKER_FILE_TEXT,
    EXTRACTION_SUFFIX
)

from utilities import (
    get_optimal_block_size,
    generate_unique_file_name,
    generate_unique_key_file_name,
    is_old_version_file
)

from PyQt6.QtCore import QThread, pyqtSignal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

import hashlib
import tarfile
import os


class EncryptionThread(QThread):
    """QThread implementation for performing file encryption operations.

    Handles both file and directory encryption, including:
    - AES-256 encryption in EAX mode
    - Optional separate IV key storage
    - Recovery key generation
    - Progress reporting
    - Cleanup operations

    Signals:
        progress_updated(int): Emits encryption progress percentage (0-100)
        operation_completed(str, str): Emits success notification (title, message)
        error_occurred(str, str): Emits error notification (title, message)
    """
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_path = ""
        self.password = ""
        self.separate_iv_key = False
        self.recovery_key = False
        self.remove_files_after = False
        self.show_progress = True
        self.compressed_files = []
        self.failed_files = []
        self.temp_files_to_cleanup = []

    def setup(self, file_path, password, separate_iv_key, recovery_key, remove_files_after, show_progress):
        """Configure encryption job parameters.

        Args:
            file_path: Absolute path to target file or directory
            password: Plaintext password for key derivation
            separate_iv_key: Boolean flag for IV key separation
            recovery_key: Boolean flag for recovery key generation
            remove_files_after: Boolean flag for source file cleanup
            show_progress: Boolean flag for progress reporting
        """
        self.file_path = file_path
        self.password = password
        self.separate_iv_key = separate_iv_key
        self.recovery_key = recovery_key
        self.remove_files_after = remove_files_after
        self.show_progress = show_progress

    def run(self):
        """Main encryption execution method.

        Performs the complete encryption workflow:
        1. Key derivation from password
        2. IV generation
        3. File/directory preparation
        4. Cryptographic operations
        5. Cleanup and notification
        """
        try:
            if os.path.isdir(self.file_path):
                compressed_file_path = generate_unique_file_name(self.file_path, add_extension=TEMP_EXT)
                self.compressed_files, self.failed_files = self.compress_directory(self.file_path, compressed_file_path)

                if not self.compressed_files:
                    self.error_occurred.emit("Error", "No files were successfully encrypted. You may not have permission to read/access the file(s) or the file(s) are in use by another program.")
                    return

                encrypted_file_path = generate_unique_file_name(self.file_path)
                file_to_encrypt = compressed_file_path
                self.temp_files_to_cleanup.append(compressed_file_path)
            else:
                encrypted_file_path = generate_unique_file_name(self.file_path)
                file_to_encrypt = self.file_path

            # Generate IV and key
            iv = get_random_bytes(16)
            key = hashlib.sha256(self.password.encode()).digest()
            block_size = get_optimal_block_size()

            # Handle separate IV key
            iv_file_path = None
            if self.separate_iv_key:
                iv_file_path = generate_unique_key_file_name(encrypted_file_path, add_extension=IV_KEY_EXT)
                with open(iv_file_path, "wb") as iv_file:
                    iv_file.write(iv)

            # Begin encrypted file creation
            with open(encrypted_file_path, "wb") as encrypted_file:
                file_size = os.path.getsize(file_to_encrypt)
                total_tasks = file_size
                completed_tasks = 0

                encrypted_file.write(FILE_HEADER) #  Write file header
                if not self.separate_iv_key:      # Write IV to main file if not separate
                    encrypted_file.write(iv)

                encrypted_file.write(hashlib.sha256(iv).digest()) # Write IV hash

                # Write password verification
                cipher_check = AES.new(key, AES.MODE_EAX, iv)
                encrypted_file.write(cipher_check.encrypt(PASS_TEXT))

                # Encrypt and write file's data
                cipher = AES.new(key, AES.MODE_EAX, iv)
                file_data_hasher = hashlib.sha256()

                with open(file_to_encrypt, "rb") as file:
                    while True:
                        chunk = file.read(block_size)
                        if not chunk:
                            break
                        encrypted_chunk = cipher.encrypt(chunk)
                        file_data_hasher.update(encrypted_chunk)
                        encrypted_file.write(encrypted_chunk)
                        completed_tasks += len(chunk)
                        if self.show_progress:
                            self.progress_updated.emit(int((completed_tasks / total_tasks) * 100))

                encrypted_file.write(file_data_hasher.digest()) # Write data hash
                encrypted_file.write(EOF_MARKER)                # Write EOF marker

            # Handle recovery key
            if self.recovery_key:
                keyfile = generate_unique_key_file_name(encrypted_file_path, add_extension=RECOVERY_KEY_EXT)
                with open(keyfile, "w") as file:
                    file.write(hashlib.sha256(self.password.encode()).hexdigest())

            # Cleanup operations
            self._cleanup_files()

            # Post-operation reporting
            if self.failed_files:
                failed_list = "\n".join(self.failed_files[:5])
                if len(self.failed_files) > 5:
                    failed_list += f"\n...and {len(self.failed_files)-5} more"
                self.error_occurred.emit("Warning", f"{len(self.failed_files)} files couldn't be encrypted:\n{failed_list}")

            self.operation_completed.emit("Encryption Successful", "Encryption completed successfully.")

        except Exception as e:
            self.error_occurred.emit("Encryption Error", f"An error occurred: {str(e)}")
            self._cleanup_files()

    def _cleanup_files(self):
        """Handle post-encryption file cleanup.

        Manages removal of:
        - Original files (if configured)
        - Temporary working files
        - Empty directories
        """
        try:
            if self.remove_files_after:
                if os.path.isfile(self.file_path):
                    try:
                        os.remove(self.file_path)
                    except Exception:
                        pass
                elif os.path.isdir(self.file_path):
                    for file in self.compressed_files:
                        try:
                            os.remove(file)
                        except Exception:
                            pass

                    for root, dirs, files in os.walk(self.file_path, topdown=False):
                        for dir in dirs:
                            dir_path = os.path.join(root, dir)
                            try:
                                if not os.listdir(dir_path):
                                    os.rmdir(dir_path)
                            except Exception:
                                pass

            for temp_file in self.temp_files_to_cleanup:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception:
                    pass

        except Exception:
            pass

    def compress_directory(self, folder_path, compressed_file_path):
        """Create tar archive of directory contents.

        Args:
            folder_path: Source directory to compress
            compressed_file_path: Destination tar file path

        Returns:
            tuple: (list of compressed files, list of failed files)
        """
        compressed_files = []
        failed_files = []

        # Create marker file
        empty_file_path = os.path.join(folder_path, MARKER_FILE)
        try:
            with open(empty_file_path, "w") as file:
                file.write(MARKER_FILE_TEXT)
            self.temp_files_to_cleanup.append(empty_file_path)
        except Exception:
            failed_files.append(empty_file_path)

        try:
            with tarfile.open(compressed_file_path, "w") as tar:
                for root, dirs, files in os.walk(folder_path):
                    for name in files:
                        file_path = os.path.join(root, name)

                        if file_path in [compressed_file_path, os.path.abspath(__file__)]:
                            continue

                        try:
                            with open(file_path, "rb") as test_file:
                                pass
                            tar.add(file_path, arcname=os.path.relpath(file_path, folder_path))
                            compressed_files.append(file_path)
                        except Exception:
                            failed_files.append(file_path)

        except Exception:
            if os.path.exists(compressed_file_path):
                try:
                    os.remove(compressed_file_path)
                except Exception:
                    pass
            raise

        return compressed_files, failed_files


class DecryptionThread(QThread):
    """QThread implementation for performing file decryption operations.

    Handles decryption of files encrypted by EncryptionThread, including:
    - AES-256 decryption in EAX mode
    - Recovery key validation
    - Separate IV key handling
    - Archive extraction
    - Progress reporting
    - Integrity verification

    Signals:
        progress_updated(int): Emits decryption progress percentage (0-100)
        operation_completed(str, str): Emits success notification (title, message)
        error_occurred(str, str): Emits error notification (title, message)
    """
    progress_updated = pyqtSignal(int)
    operation_completed = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_path = ""
        self.password = ""
        self.recovery_key_file = ""
        self.iv_key_file = ""
        self.remove_files_after = False
        self.show_progress = True
        self.hash_password = True
        self.separate_iv_key = None

    def setup(self, file_path, password, recovery_key_file, iv_key_file, remove_files_after, show_progress, hash_password, separate_iv_key):
        """Configure decryption job parameters.

        Args:
            file_path: Absolute path to encrypted file
            password: Plaintext password or recovery key data
            recovery_key_file: Path to .rkey recovery file
            iv_key_file: Path to .ivkey initialization vector file
            remove_files_after: Boolean flag for encrypted file cleanup
            show_progress: Boolean flag for progress reporting
            hash_password: Boolean flag for password hashing requirement
            separate_iv_key: Path to separate IV key file
        """
        self.file_path = file_path
        self.password = password
        self.recovery_key_file = recovery_key_file
        self.iv_key_file = iv_key_file
        self.remove_files_after = remove_files_after
        self.show_progress = show_progress
        self.hash_password = hash_password
        self.separate_iv_key = separate_iv_key

    def run(self):
        """Main decryption execution method.

        Performs the complete decryption workflow:
        1. Key material preparation
        2. File validation
        3. Cryptographic operations
        4. Integrity verification
        5. Archive extraction (if needed)
        6. Cleanup and notification
        """
        try:
            if os.path.isdir(self.file_path):
                file_name = os.path.basename(self.file_path)
                # Look for matching file in folder
                target_file = os.path.join(self.file_path, file_name + CURRENT_EXT)
                if not os.path.exists(target_file):
                    self.error_occurred.emit("File Not Found", f"Could not find encrypted file in folder: {file_name + CURRENT_EXT}")
                    return
                file_to_decrypt = target_file
            elif os.path.isfile(self.file_path):
                file_to_decrypt = self.file_path # Use file directly
            else:
                self.error_occurred.emit("ValueError", "Invalid file or folder name.")
                return

            # Check if separate IV file is given
            # Check for old version files
            if self.iv_key_file and os.path.exists(self.iv_key_file):
                old_version = is_old_version_file(file_to_decrypt, self.iv_key_file)
            else:
                old_version = is_old_version_file(file_to_decrypt)

            if old_version is not None:
                self.error_occurred.emit("Legacy File Detected", f"This file was encrypted with an older version of {APP_NAME}. Please use {APP_NAME} {old_version} to decrypt it (unsupported file format for this version).")
                return

            # Handle recovery key or password
            if self.recovery_key_file and os.path.exists(self.recovery_key_file):
                with open(self.recovery_key_file, "r") as key_file:
                    key_hex = key_file.read().strip()
                    key = bytes.fromhex(key_hex)
            else:
                if not self.password:
                    self.error_occurred.emit("Missing Credentials", "Password or recovery key required for decryption.")
                    return
                    
                if self.hash_password:
                    key = hashlib.sha256(self.password.encode()).digest()
                else:
                    key = bytes.fromhex(self.password)

            file_size = os.path.getsize(file_to_decrypt)
            if self.iv_key_file and os.path.exists(self.iv_key_file):
                min_size = 78 # header + hash + password_check + EOF marker
            else:
                min_size = 94 # header + IV + hash + password_check + EOF marker
            if file_size < min_size:
                self.error_occurred.emit("Invalid File", "File is too small to be valid encrypted file.")
                return

            with open(file_to_decrypt, "rb") as file:
                # Verify file header
                header = file.read(len(FILE_HEADER))
                if header != FILE_HEADER:
                    self.error_occurred.emit("Invalid File", "Not a valid encrypted file.")
                    return

                # Handle IV based on configuration
                iv = None
                if self.separate_iv_key is None:
                    iv = file.read(16)
                else:
                    pass

                stored_iv_hash = file.read(32)

                if self.separate_iv_key is not None:
                    if not os.path.exists(self.separate_iv_key):
                        self.error_occurred.emit("File Error", "Separate IV key file not found.")
                        return

                    with open(self.separate_iv_key, "rb") as iv_file:
                        iv = iv_file.read(16)

                    if len(iv) != 16:
                        self.error_occurred.emit("File Error", "Invalid IV key file size.")
                        return

                computed_iv_hash = hashlib.sha256(iv).digest()
                if stored_iv_hash != computed_iv_hash:
                    self.error_occurred.emit("Integrity Error", "IV hash mismatch.")
                    return

                # Password verification
                encrypted_password_check = file.read(8)
                cipher_check = AES.new(key, AES.MODE_EAX, iv)
                password_check = cipher_check.decrypt(encrypted_password_check)
                if password_check != PASS_TEXT:
                    self.error_occurred.emit("Decryption Error", "Incorrect password or key.")
                    return

                # Prepare for decryption
                cipher = AES.new(key, AES.MODE_EAX, iv)
                file_data_hasher = hashlib.sha256()

                # Calculate data boundaries
                data_offset = (3 + (0 if self.separate_iv_key is not None else 16) + 32 + 8)
                data_size = (file_size - data_offset - 32 - 3)
                remaining = data_size
                completed_tasks = 0
                block_size = get_optimal_block_size()

                # Prepare output location
                encrypted_file_dir = os.path.dirname(file_to_decrypt)
                base_file_name = os.path.basename(file_to_decrypt)
                if base_file_name.endswith(CURRENT_EXT):
                    base_name = os.path.splitext(os.path.basename(base_file_name))[0]
                else:
                    base_name = base_file_name

                extraction_dir = os.path.join(encrypted_file_dir, base_name + EXTRACTION_SUFFIX)
                counter = 1
                while os.path.exists(extraction_dir):
                    extraction_dir = os.path.join(encrypted_file_dir, base_name + f"{EXTRACTION_SUFFIX}_{counter}")
                    counter += 1
                os.makedirs(extraction_dir)

                decrypted_file_path = os.path.join(extraction_dir, base_name)

                # Decrypt data
                with open(decrypted_file_path, "wb") as decrypted_file:
                    while remaining > 0:
                        chunk_size = min(block_size, remaining)
                        encrypted_chunk = file.read(chunk_size)
                        file_data_hasher.update(encrypted_chunk)
                        decrypted_chunk = cipher.decrypt(encrypted_chunk)
                        decrypted_file.write(decrypted_chunk)
                        remaining -= chunk_size
                        completed_tasks += chunk_size
                        completed_percent = (completed_tasks / data_size) * 100
                        if self.show_progress:
                            self.progress_updated.emit(int(completed_percent))

                # Verify data integrity but continue regardless
                stored_file_hash = file.read(32)
                computed_file_hash = file_data_hasher.digest()
                if stored_file_hash != computed_file_hash:
                    self.error_occurred.emit("Data Integrity Warning", "Data hash mismatch - file may be corrupted but decryption completed.")

                # Verify EOF marker
                eof_marker = file.read(len(EOF_MARKER))
                if eof_marker != EOF_MARKER:
                    self.error_occurred.emit("File Format Error", "Missing end marker - file may be incomplete.")

            # Handle archive extraction
            if tarfile.is_tarfile(decrypted_file_path):
                with tarfile.open(decrypted_file_path, "r") as tar_ref:
                    files_list = tar_ref.getnames()
                
                # Only extract if our marker file is present
                if MARKER_FILE in files_list:
                    with tarfile.open(decrypted_file_path, "r") as tar_ref:
                        tar_ref.extractall(extraction_dir)
                    
                    # Clean up marker and tar file
                    marker_path = os.path.join(extraction_dir, MARKER_FILE)
                    if os.path.exists(marker_path):
                        os.remove(marker_path)
                    os.remove(decrypted_file_path)

            # Cleanup operations
            if self.remove_files_after:
                os.remove(file_to_decrypt)
                if self.separate_iv_key is not None and os.path.exists(self.separate_iv_key):
                    os.remove(self.separate_iv_key)
                if self.recovery_key_file and os.path.exists(self.recovery_key_file):
                    os.remove(self.recovery_key_file)

            self.operation_completed.emit("Decryption Successful", "Decryption completed successfully.")

        except Exception as e:
            self.error_occurred.emit("Error", f"An error occurred: {str(e)}")

