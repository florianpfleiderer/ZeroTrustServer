from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
import re
from typing import Optional

from cryptography.fernet import Fernet
from pathlib import Path

KEY_FILE = Path("data/client/metadata/secret.key").resolve()
METADATA_FOLDER = Path("data/client/metadata").resolve()
CLIENT_DOWNLOADS = Path("data/client/downloaded_files").resolve()


def encrypt_fek(fek: bytes, master_key: bytes) -> bytes:
    """Encrypt the FEK using the master key.

    Args:
    ----
        fek (bytes): the file encryption key
        master_key (bytes): the master key

    Raises:
    ------
        ValueError: if the master key is not 32 bytes long

    Returns:
    -------
        bytes: the encrypted FEK
    """
    if len(master_key) != 32:
        msg = "Master key must be 32 bytes long."
        raise ValueError(msg)
    b64_key = base64.urlsafe_b64encode(master_key)
    fernet = Fernet(b64_key)
    return fernet.encrypt(fek)


def decrypt_fek(encrypted_fek: bytes, master_key: bytes) -> bytes:
    """Decrypt the FEK using the master key.

    Args:
    ----
        encrypted_fek (bytes): the encrypted file encryption key
        master_key (bytes): the master key

    Returns:
    -------
        bytes: the decrypted FEK
    """
    b64_key = base64.urlsafe_b64encode(master_key)
    fernet = Fernet(b64_key)
    return fernet.decrypt(encrypted_fek)


def sanitize_filename(filename) -> str:
    """Removes any path information from the filename.

    Prevents directory traversal attacks like inserting ../../../etc/passwd.
    """
    return re.sub(r"[^\w\-.]", "_", Path(filename).name)


def store_file_metadata(
    encrypted_fek: bytes, filename: str, enc_filename: bytes, filepath: str
) -> None:
    """Store the encrypted FEK, salt, and the original filename in a file.

    Args:
    ----
        encrypted_fek (bytes): the encrypted file encryption key
        salt (bytes): the salt
        filename (str): the filename
    """
    original_filename = sanitize_filename(filename)
    filename = original_filename.split(".")[0]
    filepath = Path(filepath)
    if not filepath.exists():
        filepath.mkdir(parents=True, exist_ok=True)
    filepath = filepath / filename
    with Path(filepath.with_suffix(".meta")).open("wb") as file:
        file.write(len(encrypted_fek).to_bytes(4, "big"))
        file.write(encrypted_fek)
        file.write(enc_filename)


def load_file_metadata(
    file_identifier: str, user_id: str, user_path: str
) -> tuple[bytes, bytes]:
    """Load the encrypted FEK, salt and filename from a file.

    Args:
    ----
        filename (str): the filename

    Returns:
    -------
        tuple[bytes, bytes]: the encrypted FEK and filename
    """
    filename = sanitize_filename(file_identifier)
    filepath = Path(user_path) / user_id / f"{filename}.meta"
    with Path(filepath).open("rb") as f:
        content = f.read()
    length = int.from_bytes(content[:4], "big")
    encrypted_fek = content[4 : 4 + length]
    enc_filename = content[4 + length :].decode("utf-8")
    return encrypted_fek, enc_filename


def encrypt_file(file_path: str, key: bytes) -> bytes:
    """Encrypts the file and saves it in the path given with '.enc'

    Args:
    ----
        file_path (str): the absolute or relative path to the file
        key (bytes): the master key

    Returns:
    -------
        str: the path of the encrypted file
    """
    fernet = Fernet(key)
    with Path(file_path).open("rb") as file:
        plaintext = file.read()
    return fernet.encrypt(plaintext)
    # encrypted_file_path = file_path + ".enc"
    # with open(encrypted_file_path, "wb") as enc_file:
    #     enc_file.write(ciphertext)
    # return encrypted_file_path


def decrypt_file(
    key: bytes,
    filename: str | None = None,
    file_path: str = None,
    file_data: bytes = None,
) -> str:
    """Decryptes the file at given path or the file driectly.

    Args:
    ----
        file_path (str, optional): relative or absolute path
        key (bytes): the master key
        filename (str, optional): the name of the file. Defaults to None.

    Returns:
    -------
        str: the path of the decrypted file
    """
    fernet = Fernet(key)
    if file_path is not None:
        with Path(file_path).open("rb") as enc_file:
            ciphertext = enc_file.read()
        plaintext = fernet.decrypt(ciphertext)
        decrypted_file_path = str(file_path).removesuffix(".enc")

        with Path(decrypted_file_path).open("wb") as dec_file:
            dec_file.write(plaintext)
    elif file_data is not None:
        plaintext = fernet.decrypt(file_data)
        decrypted_file_path = CLIENT_DOWNLOADS / filename
        with Path(decrypted_file_path).open("wb") as dec_file:
            dec_file.write(plaintext)
    return decrypted_file_path


def hash_filename(filename: str, key: bytes) -> str:
    """Produced a hashed filename from the given one,

    Args:
    ----
        filename (str): the name of the file (including ending)
        key (bytes): master key

    Returns:
    -------
        str: the hash representing the filename
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(filename, str):
        filename = filename.encode("utf-8")
    hmac_obj = hmac.new(key, filename, hashlib.sha256)
    return hmac_obj.hexdigest()


def save_encrypted_file(
    filepath: str, file_identifier: bytes, encrypted_data: bytes
) -> None:
    """Saves the encrypted data to a file.

    Args:
    ----
        filepath (str): Absolute path to the file
        file_identifier (bytes): hash of the filename
        encrypted_data (bytes): ciphertext
    """
    filepath = Path(filepath)
    filepath.mkdir(parents=True, exist_ok=True)

    Path.chmod(filepath, stat.S_IRWXU)

    file_save_path = filepath / f"{file_identifier}.enc"
    with Path(file_save_path).open("wb") as f:
        f.write(encrypted_data)

    Path.chmod(file_save_path, stat.S_IRWXU)
