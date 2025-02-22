from __future__ import annotations

import email
import getpass
import base64
from hmac import new
import json
import logging
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Optional

import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from utils.certificates import (
    check_certificate_validity,
    encrypt_user_register,
    decrypt_user_register,
    generate_csr,
    generate_private_key,
    load_cert_from_disk,
    load_key_from_disk,
    save_cert_to_disk,
    save_key_to_disk,
    serialise_certificate,
    sign_certificate_request,
)
from utils.users import (
    add_user_to_register,
    authenticate_user,
    check_existing_user,
    get_user_id,
    get_user_master_key,
    register_client_user,
    remove_user_from_register,
)
from utils.utils import (
    decrypt_fek,
    decrypt_file,
    encrypt_fek,
    encrypt_file,
    hash_filename,
    load_file_metadata,
    sanitize_filename,
    store_file_metadata,
)
from utils.req_utils import (
    get_user_cert,
    get_user_key,
    get_user_register,
)

API_TOKEN = os.getenv("API_TOKEN", "MYSECRETTOKEN")
SERVER_URL = "https://localhost:30614"
DOWNLOAD_FOLDER = Path("data/client/downloaded_files").resolve()
USERPATH = Path("data/client/users").resolve()
CLIENT_FILES = Path("data/client/files").resolve()
CA_PATH = Path("data/certificates").resolve()
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)


def register_user(username: str, password: str, path: Path = USERPATH) -> None:
    """Send the unique user ID (hashed username) and the public key to the server.

    The server returns a signed certificate, which is then stored on the client side.
    """
    private_key = generate_private_key()
    # send the public key and unique ID to the server
    unique_user_id: str = uuid.uuid4().hex
    cert_sign_request = generate_csr(private_key, unique_user_id)

    if check_existing_user(username, USERPATH):
        logger.info("User already exists.")
        return

    # sign certificate with the authority
    ca_key = load_key_from_disk(CA_PATH, "ca_private_key.pem")
    ca_cert = load_cert_from_disk(CA_PATH, "ca_certificate.pem")
    certificate = sign_certificate_request(
        csr=cert_sign_request,
        ca_key=ca_key,
        ca_cert=ca_cert,
    )
    userpath = path / unique_user_id
    if not userpath.exists():
        userpath.mkdir(parents=True)

    save_key_to_disk(private_key, userpath, f"{unique_user_id}.pem")
    save_cert_to_disk(certificate, userpath, f"{unique_user_id}_cert.pem")

    email = input("Enter your email address: ")

    # send user_id and certificate to the server
    try:
        response = requests.post(
            f"{SERVER_URL}/register",
            json={
                "username": username,
                "user_id": unique_user_id,
                "email": email,
                "certificate": serialise_certificate(certificate),
            },
            headers={"Authorization": API_TOKEN},
            cert=(
                userpath / f"{unique_user_id}_cert.pem",
                userpath / f"{unique_user_id}.pem",
            ),
            verify=CA_CERT_PATH,
            timeout=10,
        )
        response.raise_for_status()
        json_response = response.json()
        logger.info(json_response.get("message", "No message in response."))
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        if userpath.exists():
            shutil.rmtree(userpath)
        return

    mfa_code = input("Enter the 2FA code: ")

    response = requests.post(
        f"{SERVER_URL}/verify",
        json={
            "username": username,
            "user_id": unique_user_id,
            "mfa": mfa_code,
            "certificate": serialise_certificate(certificate),
        },
        headers={"Authorization": API_TOKEN},
        cert=(
            userpath / f"{unique_user_id}_cert.pem",
            userpath / f"{unique_user_id}.pem",
        ),
        verify=CA_CERT_PATH,
        timeout=10,
    )
    json_response = response.json()
    logger.info(json_response.get("message", "No message in response."))
    if response.status_code == 600:
        logger.info("Verification failed.")
        if userpath.exists():
            shutil.rmtree(userpath)
        return
    # store user data on client side
    add_user_to_register(username, unique_user_id, USERPATH)
    register_client_user(username, password, userpath, unique_user_id)


def remove_user(
    username: str,
    user_id: str,
    path: Path = USERPATH,
    user_master_key: Optional[bytes] = None,
) -> None:
    """This method sends the unique user ID (hashed username) to the server to
    remove the user.

    The server should remove the user. The client should remove the user from
    the client side.

    Args:
    ----
        username (str): the username of the user to remove
        password (str): the password of the user to remove
        path (str): the path to the user data
    """
    if not check_existing_user(username, USERPATH):
        logger.info("User does not exist.")
        return
    userpath = path / user_id
    # look at folder and retrtieve all basenames of .meta files
    meta_files = [
        f for f in userpath.iterdir() if f.is_file() and f.suffix == ".meta"
    ]
    hashed_filenames = []
    for meta_file in meta_files:
        file_identifier = meta_file.stem
        logger.debug(f"remove_user(): File identifier: {file_identifier}")
        try:
            encrypted_fek, filename = load_file_metadata(
                file_identifier, user_id, USERPATH
            )
            fek = decrypt_fek(encrypted_fek, user_master_key)
            filename = decrypt_fek(filename, user_master_key)
            logger.debug(f"remove_user(): filename: {filename}")
            hashed_filenames.append(hash_filename(filename, fek))
        except FileNotFoundError:
            logger.info("No metadata for requested file.")
            return
        except InvalidToken:
            logger.info("No permission to download this file.")
            return

    logger.debug(f"remove_user(): Hashed filenames: {hashed_filenames}")
    # retrive the user register and key from the server
    try:
        encrypted_key: bytes = get_user_key(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return
    try:
        encrypted_user_register = get_user_register(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return

    decrypted_user_register, cipher = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]
    for user in decrypted_user_register:
        if user["user_id"] == user_id:
            decrypted_user_register.remove(user)
    print("decrypted user reg", decrypted_user_register)

    # Encode bytes to base64 to make them JSON serializable
    for user in decrypted_user_register:
        if "shared_with_me" in user:
            for shared_file in user["shared_with_me"]:
                for file_id, file_data in shared_file.items():
                    file_data["encrypted_fek"] = base64.b64encode(
                        file_data["encrypted_fek"]
                    ).decode("utf-8")
                    file_data["signature"] = base64.b64encode(
                        file_data["signature"]
                    ).decode("utf-8")

    encrypted_user_register = encrypt_user_register(
        decrypted_user_register, user_id, cipher=cipher
    )
    # send the hashed filenames to the server
    json_data = {
        "user_id": user_id,
        "filenames": json.dumps(hashed_filenames),
    }
    headers = {"Authorization": API_TOKEN}
    cert = (
        USERPATH / user_id / f"{user_id}_cert.pem",
        USERPATH / user_id / f"{user_id}.pem",
    )
    verify = CA_CERT_PATH
    try:
        response = requests.post(
            f"{SERVER_URL}/remove",
            data=json_data,
            files={"user_register": encrypted_user_register},
            headers=headers,
            cert=cert,
            verify=verify,
            timeout=10,
        )
        json_response = response.json()
        logger.info(json_response.get("message", "No message in response."))
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return
    if response.status_code in [200, 201]:
        userpath = path / user_id
        if userpath.exists():
            shutil.rmtree(userpath)
        # remove user from client register
        if remove_user_from_register(username, USERPATH):
            logger.info("User removed.")


def show_registered_users(
    username: str, user_id: str, path: Path = USERPATH
) -> None:
    """If you are registered, you can retrieve the ids of other registered users."""
    if not check_existing_user(username, USERPATH):
        logger.info("User does not exist.")
        return

    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return
    decrypted_user_register, _ = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]
    for user in decrypted_user_register:
        logger.info(f"Username: {user['username']}")


def show_files(user_id: str, user_key: bytes, path: Path = USERPATH) -> bool:
    """Retrieves the uploaded files of the user by looking at the <filename>.meta files
    in the user folder. The metadata files contain the original filename."""
    userpath = path / user_id
    # look at folder and retrtieve all basenames of .meta files
    meta_files = [
        f for f in userpath.iterdir() if f.is_file() and f.suffix == ".meta"
    ]
    filenames = []
    for meta_file in meta_files:
        file_identifier = meta_file.stem
        try:
            _, enc_filename = load_file_metadata(
                file_identifier, user_id, USERPATH
            )
            filenames.append(decrypt_fek(enc_filename, user_key))
        except FileNotFoundError:
            logger.info("No metadata for requested file.")
            return None
        except InvalidToken:
            logger.info("No permission to download this file.")
            return None

    # get list of shared files with me
    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return None
    decrypted_user_register, cipher = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]
    shared_filenames = []
    for user in decrypted_user_register:
        if user["user_id"] == user_id:
            shared_filenames.extend(
                [
                    file_data["filename"] + " from " + file_data["sender_name"]
                    for shared_file in user.get("shared_with_me", [])
                    for file_data in shared_file.values()
                ]
            )

    if not filenames:
        logger.info("No files uploaded yet.")
    else:
        logger.info("Uploaded files:")
        for filename in filenames:
            logger.info(filename.decode("utf-8"))
    logger.info("Shared files:")
    for filename in shared_filenames:
        logger.info(filename)
    return True


def upload_file(
    file_name: str,
    user_master_key: Optional[bytes] = None,
    user_id: Optional[str] = None,
) -> None:
    """Uploads the file via POST request to the server

    Args:
    ----
        file_name (str): file must be in CLIENT_FILES
    """
    if not Path(CLIENT_FILES / file_name).exists():
        raise FileNotFoundError
    file_path = Path(CLIENT_FILES / file_name).resolve()
    fek = Fernet.generate_key()
    enc_file = encrypt_file(file_path, fek)
    # sign the file with the user private key
    private_key: rsa.RSAPrivateKey = load_key_from_disk(
        USERPATH / user_id, f"{user_id}.pem"
    )
    signed_file = private_key.sign(
        enc_file,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    original_filename = file_path.name
    hashed_filename = hash_filename(original_filename, fek)
    encrypted_fek: bytes = encrypt_fek(fek, user_master_key)
    encrypted_filename = encrypt_fek(
        original_filename.encode(), user_master_key
    )
    logger.debug(f"upload_file(): Hashed filename: {hashed_filename}")
    logger.debug(f"upload_file(): Encrypted filename: {encrypted_filename}")
    enc_file_path = USERPATH / user_id

    store_file_metadata(
        encrypted_fek, original_filename, encrypted_filename, enc_file_path
    )
    # send both file and signature combined
    files = {"file": (hashed_filename, enc_file + signed_file)}
    headers = {"Authorization": API_TOKEN}
    cert = (
        USERPATH / user_id / f"{user_id}_cert.pem",
        USERPATH / user_id / f"{user_id}.pem",
    )
    verify = CA_CERT_PATH
    try:
        response = requests.post(
            f"{SERVER_URL}/upload",
            files=files,
            headers=headers,
            cert=cert,
            verify=verify,
            timeout=10,
        )
        response.raise_for_status()
        json_response = response.json()
        logger.info(json_response.get("message", "No message in response."))
    except requests.exceptions.RequestException as e:
        logger.exception("An error occurred: %s", e)


def download_file(
    filename: str,
    user_master_key: Optional[bytes] = None,
    user_id: Optional[str] = None,
) -> None:
    """Retrieves a file using the filename (including ending) via the
    hashing function.

    Args:
    ----
        filename (str): the name including ending (NOT the path)
    """
    file_identifier = filename.split(".")[0]
    try:
        encrypted_fek, _ = load_file_metadata(
            file_identifier, user_id, USERPATH
        )
        fek = decrypt_fek(encrypted_fek, user_master_key)
    except FileNotFoundError:
        logger.info("No metadata for requested file.")
        return
    except InvalidToken:
        logger.info("No permission to download this file.")
        return
    hashed_filename = hash_filename(filename, fek)
    headers = {"Authorization": API_TOKEN}
    cert = (
        USERPATH / user_id / f"{user_id}_cert.pem",
        USERPATH / user_id / f"{user_id}.pem",
    )
    verify = CA_CERT_PATH
    try:
        response = requests.get(
            f"{SERVER_URL}/download/{hashed_filename}",
            headers=headers,
            cert=cert,
            verify=verify,
            timeout=10,
        )
    except requests.exceptions.SSLError as se:
        logger.exception("download_file(): An ssl error occurred: %s", se)
        return
    except requests.exceptions.RequestException as re:
        logger.exception("download_file(): An error occurred.")
        return
    if response.status_code == 200:
        if not DOWNLOAD_FOLDER.exists():
            DOWNLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

        encrypted_file = response.content
        signature_length = 256
        encrypted_file, signature = (
            encrypted_file[:-signature_length],
            encrypted_file[-signature_length:],
        )
        # check signature of file with my public key
        public_key = load_cert_from_disk(
            USERPATH / user_id, f"{user_id}_cert.pem"
        ).public_key()
        public_key.verify(
            signature,
            encrypted_file,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        decrypted_file_path = decrypt_file(
            fek, filename=filename, file_data=encrypted_file
        )
        logger.info(f"File downloaded and decrypted to {decrypted_file_path}")
    else:
        logger.info(
            f"Failed to download file. Status code: {response.status_code}"
        )


def share_file(
    file_to_share: str,
    share_with: str,
    user_id: str,
    username: str,
    user_master_key: Optional[bytes] = None,
) -> bool | None:
    """Shares a file with another user.

    The users are retrieve using the show registered users function.
    The user then selects a file to share. Uploaded files metadata in
    client user folder is used for this (since the client knows what files
    he has uploaded).

    The unique fek for the relevant file is then encrypted with the receiving
    users public key.
    The enc.meta file is retrived from the server and the encrypted fek, along
    with the signature is stored in the metadata file.
    The metadata file then looks like this:
    [
        {
            "username": "q",
            "unique_id": "0a2da6086c5c44de9725ecab2c073987"
            "shared_with_me": [
                "file_id_1": {
                "encrypted_fek": "base64-encoded...",
                "signature": "base64-encoded...",
                "sender_id": "unique-id"
                },
                ...
            ]
        },
        {
            "username": "w",
            "unique_id": "2dc9d9ce86c74dcaa5a4a7f097ec3f1c"
        },
        {
            "username": "e",
            "unique_id": "5535963d019e4d99af5f6c301480b86b"
        }
    ]
    Since the receiving user needs to also know the unique filename, its
    contained in the metadata file.
    """
    with Path(USERPATH / "users.json").open() as f:
        users = json.load(f)
    if not isinstance(users, list):
        users = [users]
    for user in users:
        if user["username"] == share_with:
            share_with_id = user["unique_id"]
            break

    recipient_cert: bytes = get_user_cert(share_with_id)
    recipient_cert = x509.load_pem_x509_certificate(
        recipient_cert, default_backend()
    )
    if not check_certificate_validity(recipient_cert):
        logger.info("Certificate not valid.")
        return False
    logger.debug("share_file(): cetrificate check passed.")

    # get fek and decrypt it
    file_identifier = file_to_share.split(".")[0]
    logger.debug("username: %s", username)
    try:
        encrypt_fek, enc_filename = load_file_metadata(
            file_identifier, user_id, USERPATH
        )
        fek = decrypt_fek(
            encrypt_fek,
            user_master_key,
        )
        filename = decrypt_fek(
            enc_filename,
            user_master_key,
        )
        logger.debug("share_file(): filename: %s", filename)
    except FileNotFoundError:
        logger.info("share file(): No files uploaded.")
        return None
    except InvalidToken:
        logger.info("No permission to download this file.")
        return None
    public_key = recipient_cert.public_key()
    new_encrypted_fek = public_key.encrypt(
        fek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    private_key: rsa.RSAPrivateKey = load_key_from_disk(
        USERPATH / user_id, f"{user_id}.pem"
    )
    signature = private_key.sign(
        new_encrypted_fek,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    # request user register
    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return
    decrypted_user_register, cipher = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]
    logger.debug(
        f"share_file(): decrypted_user_register: {decrypted_user_register}"
    )
    hashed_filename = hash_filename(filename, fek)
    new_encrypted_fek = base64.b64encode(new_encrypted_fek).decode("utf-8")
    signature = base64.b64encode(signature).decode("utf-8")
    filename = filename.decode("utf-8")
    for user in decrypted_user_register:
        logger.debug("share_file(): user: %s", user)
        if user["user_id"] == share_with_id:
            if "shared_with_me" not in user:
                user["shared_with_me"] = []
            user["shared_with_me"].append(
                {
                    hashed_filename: {
                        "encrypted_fek": new_encrypted_fek,
                        "signature": signature,
                        "sender_id": user_id,
                        "sender_name": username,
                        "filename": filename,
                    }
                }
            )
            break
    logger.debug("decrypted_reg: %s", decrypted_user_register)
    encrypted_user_register = encrypt_user_register(
        decrypted_user_register, user_id, cipher=cipher
    )
    # add an entry to the private user_id.json file
    user_file_path = Path(USERPATH / user_id / f"{user_id}.json")
    if user_file_path.exists():
        with user_file_path.open("r+") as f:
            user_data = json.load(f)
            shared_files = user_data.get("shared_files", {})
            if hashed_filename in shared_files:
                if share_with_id not in shared_files[hashed_filename]:
                    shared_files[hashed_filename].append(share_with_id)
            else:
                shared_files[hashed_filename] = [share_with_id]
            user_data["shared_files"] = shared_files
            f.seek(0)
            json.dump(user_data, f, indent=4)
            f.truncate()
    else:
        user_data = {"shared_files": {hashed_filename: [share_with_id]}}
        with user_file_path.open("w") as f:
            json.dump(user_data, f, indent=4)

    # send register back to server
    json_data = {
        "user_id": user_id,
    }
    headers = {"Authorization": API_TOKEN}
    cert = (
        USERPATH / user_id / f"{user_id}_cert.pem",
        USERPATH / user_id / f"{user_id}.pem",
    )
    verify = CA_CERT_PATH
    try:
        response = requests.post(
            f"{SERVER_URL}/share_file",
            data=json_data,
            files={"user_register": encrypted_user_register},
            headers=headers,
            cert=cert,
            verify=verify,
            timeout=10,
        )
        json_response = response.json()
        logger.info(json_response.get("message", "No message in response."))
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return False
    return True


def get_shared_file(
    filename: str, user_id: str, user_master_key: bytes
) -> None:
    # request user register
    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        logger.exception("An error occurred")
        return
    decrypted_user_register, _ = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]

    sender_id = None
    filehash = None
    for user in decrypted_user_register:
        if "shared_with_me" in user and user["user_id"] == user_id:
            for shared_file in user["shared_with_me"]:
                for file_id, file_data in shared_file.items():
                    logger.debug(f"get_shared_file(): file_data: {file_data}")
                    logger.debug(f"get_shared_file(): filename: {filename}")
                    if file_data["filename"] == filename:
                        logger.debug("get_shared_file(): Found file.")
                        encrypted_fek = base64.b64decode(
                            file_data["encrypted_fek"]
                        )
                        signature = base64.b64decode(file_data["signature"])
                        sender_id = file_data["sender_id"]
                        filehash = file_id
                        break
    logger.debug(f"get_shared_file(): sender_id: {sender_id}")
    if sender_id is None:
        logger.info("Permission denied.")
        return None

    logger.debug("NOTE")

    # check sender certificate
    sender_cert: bytes = get_user_cert(sender_id)
    sender_cert = x509.load_pem_x509_certificate(sender_cert, default_backend())
    if not check_certificate_validity(sender_cert):
        logger.info("Certificate not valid.")
        return False

    headers = {"Authorization": API_TOKEN}
    cert = (
        USERPATH / user_id / f"{user_id}_cert.pem",
        USERPATH / user_id / f"{user_id}.pem",
    )
    verify = CA_CERT_PATH
    try:
        response = requests.get(
            f"{SERVER_URL}/download/{filehash}",
            headers=headers,
            cert=cert,
            verify=verify,
            timeout=10,
        )
    except requests.exceptions.SSLError as se:
        logger.exception("download_file(): An ssl error occurred: %s", se)
        return
    except requests.exceptions.RequestException as re:
        logger.exception("download_file(): An error occurred.")
        return
    if response.status_code == 200:
        DOWNLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

        encrypted_file = response.content
        signature_length = 256
        encrypted_file, signature = (
            encrypted_file[:-signature_length],
            encrypted_file[-signature_length:],
        )
        # check signature of file with my public key
        public_key = x509.load_pem_x509_certificate(
            get_user_cert(sender_id), default_backend()
        ).public_key()
        public_key.verify(
            signature,
            encrypted_file,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        private_key = load_key_from_disk(USERPATH / user_id, f"{user_id}.pem")
        fek = private_key.decrypt(
            encrypted_fek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        decrypted_file_path = decrypt_file(
            fek, filename=filename, file_data=encrypted_file
        )
        logger.info(f"File downloaded and decrypted to {decrypted_file_path}")
    else:
        logger.info(
            f"Failed to download file. Status code: {response.status_code}"
        )


def main() -> None:
    """Runs client application."""
    if len(sys.argv) != 3:
        logger.info("Usage:")
        logger.info("  Register: client.py register <username>")
        logger.info("  Login: client.py login <username>")
        sys.exit(1)

    action = sys.argv[1]
    username = sys.argv[2]

    if action == "register":
        password: str = getpass.getpass("Enter password: ")
        register_user(username, password, USERPATH)

    elif action == "login":
        password: str = getpass.getpass("Enter password: ")
        if authenticate_user(username, password, USERPATH):
            unique_id = get_user_id(username, USERPATH)
            userfile_path = USERPATH / unique_id / f"{unique_id}.json"
            user_key = get_user_master_key(userfile_path, username, password)
            logger.info("Welcome %s!", username)

            # NOTE: this is for sending the test 2fa test email
            # requests.post(
            #     f"{SERVER_URL}/send_email",
            #     json={"username": username},
            #     headers={"Authorization": API_TOKEN},
            #     cert=(
            #         USERPATH / unique_id / f"{unique_id}_cert.pem",
            #         USERPATH / unique_id / f"{unique_id}.pem",
            #     ),
            #     verify=CA_CERT_PATH,
            #     timeout=10,
            # )

            # Interactive session after successful login
            while True:
                logger.info("# Please choose an action:")
                logger.info("  upload <filename>")
                logger.info("  download <filename>")
                logger.info("  show users")
                logger.info("  show files")
                logger.info("  share file <filename> <username>")
                logger.info("  get shared <filename>")
                logger.info("  remove user")
                logger.info("  logout")
                user_input = input(">").strip()

                if user_input == "logout":
                    logger.info("Logging out.")
                    break
                if user_input.startswith("upload "):
                    file_name = user_input[len("upload ") :].strip()
                    file_name = sanitize_filename(file_name)
                    try:
                        upload_file(file_name, user_key, unique_id)
                    except FileNotFoundError:
                        logger.info("File not found for upload.")
                    except Exception:
                        logger.info("Invalid input. Please try again.")
                elif user_input.startswith("download "):
                    filename = user_input[len("download ") :].strip()
                    filename = sanitize_filename(filename)
                    try:
                        download_file(filename, user_key, unique_id)
                    except InvalidSignature:
                        logger.info("File signature invalid.")
                    except Exception:
                        logger.info("Invalid input. Please try again.")
                elif user_input == "show users":
                    show_registered_users(username, unique_id, USERPATH)
                elif user_input == "show files":
                    show_files(unique_id, user_key, USERPATH)
                elif user_input.startswith("share file "):
                    try:
                        file_to_share, share_with = user_input[
                            len("share file ") :
                        ].split()
                    except ValueError:
                        logger.info("Invalid input. Please try again.")
                        continue
                    logger.info(f"Sharing {file_to_share} with {share_with}")
                    file_to_share = sanitize_filename(file_to_share)
                    try:
                        share_file(
                            file_to_share,
                            share_with,
                            unique_id,
                            username,
                            user_key,
                        )
                    except Exception:
                        logger.info("Invalid input. Please try again.")
                elif user_input.startswith("get shared "):
                    filename = user_input[len("get shared ") :].strip()
                    filename = sanitize_filename(filename)
                    logger.debug(f"get shared: {filename}")
                    try:
                        get_shared_file(filename, unique_id, user_key)
                    except Exception as e:
                        logger.info("Invalid input. Please try again.")
                        logger.debug(e)
                elif user_input == "remove user":
                    remove_user(
                        username, unique_id, USERPATH, user_master_key=user_key
                    )
                    logger.info("User removed. Logging out.")
                    break
                else:
                    logger.info("Invalid command. Please try again.")
        else:
            logger.info("Authentication failed.")

    else:
        logger.info('Invalid action. Use "register" or "login".')

    logger.info("Done.")


if __name__ == "__main__":
    main()
