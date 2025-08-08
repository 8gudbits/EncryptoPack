from constants import CURRENT_EXT

import hashlib
import psutil
import os


def get_optimal_block_size():
    """Determines the optimal block size for cryptographic operations based on available system memory.
    
    The block size is scaled according to available RAM to balance performance and memory usage.
    Falls back to 512 KiB if system memory cannot be determined.

    Returns:
        int: Optimal block size in bytes for encryption/decryption operations.
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


def generate_unique_file_name(file_path, add_extension=CURRENT_EXT):
    """Generates a unique filename by appending an extension and incrementing a counter if needed.
    
    Handles both file and directory paths. For existing paths, appends a counter to create
    a unique filename while preserving the original extension.

    Args:
        file_path: Path to the original file or directory
        add_extension: File extension to append (defaults to CURRENT_EXT)

    Returns:
        str: Absolute path to a non-existent file with the specified extension
    """
    if os.path.isfile(file_path):
        directory = os.path.dirname(file_path)
        base_name, extension = os.path.splitext(os.path.basename(file_path))
        test_path = os.path.join(directory, f"{base_name}{extension}{add_extension}")
        if not os.path.exists(test_path):
            return test_path

        counter = 1
        while True:
            test_path = os.path.join(directory, f"{base_name}_{counter}{extension}{add_extension}")
            if not os.path.exists(test_path):
                return test_path
            counter += 1

    elif os.path.isdir(file_path):
        base_folder_name = os.path.basename(os.path.normpath(file_path))
        test_path = os.path.join(file_path, f"{base_folder_name}{add_extension}")
        if not os.path.exists(test_path):
            return test_path

        counter = 1
        while True:
            unique_folder_name = f"{base_folder_name}_{counter}"
            test_path = os.path.join(file_path, unique_folder_name + add_extension)
            if not os.path.exists(test_path):
                return test_path
            counter += 1


def generate_unique_key_file_name(file_path, add_extension=".key"):
    """Generates a unique filename for cryptographic key files.

    Preserves the original filename while ensuring the output path doesn't exist
    by appending an incrementing counter if needed.

    Args:
        file_path: Path to the original file
        add_extension: Key file extension to append (defaults to ".key")

    Returns:
        str: Absolute path to a non-existent key file
    """
    # Get directory and file components
    directory = os.path.dirname(file_path)
    base_name, extension = os.path.splitext(os.path.basename(file_path))

    # First try without counter
    test_path = os.path.join(directory, f"{base_name}{extension}{add_extension}")
    if not os.path.exists(test_path):
        return test_path

    # If exists, try with counter
    counter = 1
    while True:
        test_path = os.path.join(directory, f"{base_name}_{counter}{extension}{add_extension}")
        if not os.path.exists(test_path):
            return test_path
        counter += 1


def is_old_version_file(file_path, iv_key_file=None):
    """Detect old version of EncryptoPack files.

    Args:
        file_path: Path to encrypted file
        iv_key_file: Optional path to separate IV key file

    Returns:
        str: "v1.0/v1.1" if detected, else None
    """
    try:
        # Case 1: Separate IV key provided
        if iv_key_file and os.path.exists(iv_key_file):
            # Read IV from separate file
            with open(iv_key_file, "rb") as iv_f:
                if os.path.getsize(iv_key_file) < 16:
                    return None
                iv = iv_f.read(16)

            # Read stored hash from end of encrypted file
            with open(file_path, "rb") as f:
                if os.path.getsize(file_path) < 20:
                    return None
                f.seek(-20, os.SEEK_END)
                stored_hash = f.read(20)

            # Verify hash matches
            if hashlib.sha1(iv).digest() == stored_hash:
                return "v1.0/v1.1"
            return None

        # Case 2: Embedded IV
        file_size = os.path.getsize(file_path)
        if file_size < 36:
            return None

        with open(file_path, "rb") as f:
            iv = f.read(16)
            f.seek(-20, os.SEEK_END)
            stored_hash = f.read(20)

            if hashlib.sha1(iv).digest() == stored_hash:
                return "v1.0/v1.1"

        return None
    except Exception:
        return None

