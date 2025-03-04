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
from typing import Optional, List, Dict, Any

import requests
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich.traceback import install
from rich.logging import RichHandler

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

# Set up Rich console and install Rich traceback handler
console = Console()
install()  # Install rich traceback handler

# Configure logging with Rich handler
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
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
        console.print("[bold red]User does not exist.[/bold red]")
        return

    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        console.print_exception()
        return
        
    decrypted_user_register, _ = decrypt_user_register(
        encrypted_key, encrypted_user_register, user_id
    )
    
    if not isinstance(decrypted_user_register, list):
        decrypted_user_register = [decrypted_user_register]
        
    # Create a Rich table for displaying users
    table = Table(title="Registered Users", show_header=True, header_style="bold magenta")
    table.add_column("Username", style="dim")
    table.add_column("User ID", style="dim")
    
    for user in decrypted_user_register:
        table.add_row(
            user['username'],
            user.get('unique_id', 'N/A')[:8] + "..." if user.get('unique_id') else 'N/A'
        )
    
    console.print(table)
    

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
            console.print("[bold red]No metadata for requested file.[/bold red]")
            return None
        except InvalidToken:
            console.print("[bold red]No permission to download this file.[/bold red]")
            return None

    # get list of shared files with me
    try:
        encrypted_user_register = get_user_register(user_id)
        encrypted_key = get_user_key(user_id)
    except requests.exceptions.RequestException:
        console.print_exception()
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
                    {"filename": file_data["filename"], "sender": file_data["sender_name"]}
                    for shared_file in user.get("shared_with_me", [])
                    for file_data in shared_file.values()
                ]
            )

    # Create tables for display
    if not filenames and not shared_filenames:
        console.print(Panel("[italic]No files found[/italic]", title="Files", border_style="blue"))
        return True
        
    # Display uploaded files
    if filenames:
        uploaded_table = Table(title="Your Uploaded Files", show_header=True, header_style="bold blue")
        uploaded_table.add_column("Filename", style="dim")
        
        for filename in filenames:
            try:
                decoded_filename = filename.decode("utf-8")
                uploaded_table.add_row(decoded_filename)
            except UnicodeDecodeError:
                uploaded_table.add_row("[red]Invalid filename encoding[/red]")
                
        console.print(uploaded_table)
    else:
        console.print(Panel("[italic]No uploaded files[/italic]", title="Your Files", border_style="blue"))
    
    # Display shared files
    if shared_filenames:
        shared_table = Table(title="Files Shared With You", show_header=True, header_style="bold green")
        shared_table.add_column("Filename", style="dim")
        shared_table.add_column("Shared By", style="dim")
        
        for file_info in shared_filenames:
            shared_table.add_row(file_info["filename"], file_info["sender"])
            
        console.print(shared_table)
    else:
        console.print(Panel("[italic]No shared files[/italic]", title="Shared Files", border_style="green"))
        
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
        console.print(f"[bold red]File not found: {file_name}[/bold red]")
        raise FileNotFoundError
        
    file_path = Path(CLIENT_FILES / file_name).resolve()
    file_size = file_path.stat().st_size
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        # Step 1: Generate encryption key
        prepare_task = progress.add_task("[green]Preparing file...", total=100)
        
        fek = Fernet.generate_key()
        progress.update(prepare_task, advance=20)
        
        # Step 2: Encrypt file
        progress.update(prepare_task, description="[green]Encrypting file...")
        enc_file = encrypt_file(file_path, fek)
        progress.update(prepare_task, advance=30)
        
        # Step 3: Sign the file
        progress.update(prepare_task, description="[green]Signing file...")
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
        progress.update(prepare_task, advance=20)
        
        # Step 4: Prepare metadata
        progress.update(prepare_task, description="[green]Preparing metadata...")
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
        progress.update(prepare_task, advance=20)
        
        # Step 5: Upload file
        progress.update(prepare_task, description="[green]Uploading file...")
        progress.update(prepare_task, completed=90)
        
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
            progress.update(prepare_task, advance=10)
            
            response.raise_for_status()
            json_response = response.json()
            
            # Show success message outside the progress bar
            console.print(f"[bold green]{json_response.get('message', 'File uploaded successfully!')}[/bold green]")
            
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Upload failed: {str(e)}[/bold red]")
            logger.debug(f"Upload error details: {e}", exc_info=True)


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
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        # Step 1: Retrieve file metadata
        prepare_task = progress.add_task("[green]Preparing download...", total=100)
        
        file_identifier = filename.split(".")[0]
        try:
            encrypted_fek, _ = load_file_metadata(
                file_identifier, user_id, USERPATH
            )
            fek = decrypt_fek(encrypted_fek, user_master_key)
            progress.update(prepare_task, advance=20)
        except FileNotFoundError:
            progress.stop()
            console.print("[bold red]No metadata for requested file.[/bold red]")
            return
        except InvalidToken:
            progress.stop()
            console.print("[bold red]No permission to download this file.[/bold red]")
            return
            
        # Step 2: Calculate filename hash
        progress.update(prepare_task, description="[green]Preparing request...")
        hashed_filename = hash_filename(filename, fek)
        headers = {"Authorization": API_TOKEN}
        cert = (
            USERPATH / user_id / f"{user_id}_cert.pem",
            USERPATH / user_id / f"{user_id}.pem",
        )
        verify = CA_CERT_PATH
        progress.update(prepare_task, advance=10)
        
        # Step 3: Send download request
        progress.update(prepare_task, description="[green]Downloading file...")
        try:
            response = requests.get(
                f"{SERVER_URL}/download/{hashed_filename}",
                headers=headers,
                cert=cert,
                verify=verify,
                timeout=10,
                stream=True,  # Use streaming for better progress reporting
            )
            progress.update(prepare_task, advance=20)
        except requests.exceptions.SSLError as se:
            progress.stop()
            console.print(f"[bold red]SSL error during download: {str(se)}[/bold red]")
            logger.debug(f"SSL error details: {se}", exc_info=True)
            return
        except requests.exceptions.RequestException as re:
            progress.stop()
            console.print(f"[bold red]Download failed: {str(re)}[/bold red]")
            logger.debug(f"Download error details: {re}", exc_info=True)
            return
            
        if response.status_code == 200:
            # Step 4: Process downloaded file
            progress.update(prepare_task, description="[green]Processing file...")
            
            if not DOWNLOAD_FOLDER.exists():
                DOWNLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

            encrypted_file = response.content
            signature_length = 256
            encrypted_file, signature = (
                encrypted_file[:-signature_length],
                encrypted_file[-signature_length:],
            )
            progress.update(prepare_task, advance=20)
            
            # Step 5: Verify signature
            progress.update(prepare_task, description="[green]Verifying signature...")
            try:
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
                progress.update(prepare_task, advance=15)
            except InvalidSignature:
                progress.stop()
                console.print("[bold red]Invalid file signature. The file may have been tampered with.[/bold red]")
                return
                
            # Step 6: Decrypt file
            progress.update(prepare_task, description="[green]Decrypting file...")
            decrypted_file_path = decrypt_file(
                fek, filename=filename, file_data=encrypted_file
            )
            progress.update(prepare_task, advance=15, completed=100)
            
            # Success message
            console.print(f"[bold green]File downloaded and decrypted to:[/bold green] [blue]{decrypted_file_path}[/blue]")
        else:
            progress.stop()
            console.print(f"[bold red]Failed to download file. Status code: {response.status_code}[/bold red]")


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
    # Try to open the users.json file
    try:
        with Path(USERPATH / "users.json").open() as f:
            users = json.load(f)
    except FileNotFoundError:
        logger.error("ERROR: users.json file not found. Please register users first.")
        return False
    except json.JSONDecodeError:
        logger.error("ERROR: users.json contains invalid JSON data.")
        return False
        
    if not isinstance(users, list):
        users = [users]
        
    # Find the user to share with
    share_with_id = None
    for user in users:
        if user["username"] == share_with:
            share_with_id = user["unique_id"]
            break
            
    if share_with_id is None:
        logger.error(f"ERROR: User '{share_with}' not found in registered users. Please check the username and try again.")
        return False

    # Get recipient certificate
    try:
        recipient_cert: bytes = get_user_cert(share_with_id)
        recipient_cert = x509.load_pem_x509_certificate(
            recipient_cert, default_backend()
        )
    except Exception as e:
        logger.error(f"ERROR: Failed to get certificate for user '{share_with}': {str(e)}")
        return False
        
    if not check_certificate_validity(recipient_cert):
        logger.error(f"ERROR: Certificate for user '{share_with}' is not valid.")
        return False
    logger.debug("share_file(): certificate check passed.")

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
        logger.error(f"ERROR: File '{file_to_share}' not found. Please check that you have uploaded this file.")
        return None
    except InvalidToken:
        logger.error("ERROR: No permission to access this file. Invalid encryption key.")
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
    console.print(Panel.fit(
        "[bold blue]Secure File Sharing Client[/bold blue]\n"
        "[dim]A secure way to share files with others[/dim]",
        border_style="blue",
        padding=(1, 2)
    ))
    
    if len(sys.argv) != 3:
        console.print(Panel(
            "[bold]Usage:[/bold]\n"
            "  [green]Register:[/green] client.py register <username>\n"
            "  [green]Login:[/green] client.py login <username>",
            title="Help",
            border_style="yellow"
        ))
        sys.exit(1)

    action = sys.argv[1]
    username = sys.argv[2]

    if action == "register":
        console.print("[yellow]Registration Mode[/yellow]")
        password: str = getpass.getpass("Enter password: ")
        
        with console.status("[bold green]Registering user...[/bold green]"):
            register_user(username, password, USERPATH)

    elif action == "login":
        console.print("[yellow]Login Mode[/yellow]")
        password: str = getpass.getpass("Enter password: ")
        
        with console.status("[bold green]Authenticating...[/bold green]"):
            auth_success = authenticate_user(username, password, USERPATH)
            
        if auth_success:
            unique_id = get_user_id(username, USERPATH)
            userfile_path = USERPATH / unique_id / f"{unique_id}.json"
            user_key = get_user_master_key(userfile_path, username, password)
            
            console.print(f"[bold green]Welcome, {username}![/bold green]")

            # Interactive session after successful login
            while True:
                # Display menu in a panel
                menu = Panel(
                    "\n".join([
                        "[bold cyan]1. upload <filename>[/bold cyan] - Upload a file to the server",
                        "[bold cyan]2. download <filename>[/bold cyan] - Download a file from the server",
                        "[bold cyan]3. show users[/bold cyan] - Show all registered users",
                        "[bold cyan]4. show files[/bold cyan] - Show your files and files shared with you",
                        "[bold cyan]5. share file <filename> <username>[/bold cyan] - Share a file with another user",
                        "[bold cyan]6. get shared <filename>[/bold cyan] - Get a file shared with you",
                        "[bold cyan]7. remove user[/bold cyan] - Delete your account",
                        "[bold cyan]8. logout[/bold cyan] - Exit the application",
                    ]),
                    title="Available Commands",
                    border_style="blue"
                )
                console.print(menu)
                
                # Get user input with Rich prompt
                user_input = Prompt.ask("[bold blue]>[/bold blue]").strip()

                # Handle numbered commands
                if user_input == "8" or user_input == "logout":
                    console.print("[yellow]Logging out...[/yellow]")
                    break
                    
                # Handle upload command (1 or upload...)
                elif user_input == "1" or user_input.startswith("upload "):
                    if user_input == "1":
                        file_name = Prompt.ask("[bold blue]Enter filename to upload[/bold blue]")
                    else:
                        file_name = user_input[len("upload ") :].strip()
                    
                    file_name = sanitize_filename(file_name)
                    try:
                        upload_file(file_name, user_key, unique_id)
                    except FileNotFoundError:
                        console.print(f"[bold red]File not found: {file_name}[/bold red]")
                    except Exception as e:
                        console.print(f"[bold red]Error: {str(e)}[/bold red]")
                        
                # Handle download command (2 or download...)
                elif user_input == "2" or user_input.startswith("download "):
                    if user_input == "2":
                        filename = Prompt.ask("[bold blue]Enter filename to download[/bold blue]")
                    else:
                        filename = user_input[len("download ") :].strip()
                        
                    filename = sanitize_filename(filename)
                    try:
                        download_file(filename, user_key, unique_id)
                    except InvalidSignature:
                        console.print("[bold red]File signature invalid.[/bold red]")
                    except Exception as e:
                        console.print(f"[bold red]Error: {str(e)}[/bold red]")
                        
                # Handle show users command (3 or show users)
                elif user_input == "3" or user_input == "show users":
                    show_registered_users(username, unique_id, USERPATH)
                    
                # Handle show files command (4 or show files)
                elif user_input == "4" or user_input == "show files":
                    show_files(unique_id, user_key, USERPATH)
                    
                # Handle share file command (5 or share file...)
                elif user_input == "5" or user_input.startswith("share file "):
                    if user_input == "5":
                        file_to_share = Prompt.ask("[bold blue]Enter filename to share[/bold blue]")
                        share_with = Prompt.ask("[bold blue]Enter username to share with[/bold blue]")
                    else:
                        try:
                            file_to_share, share_with = user_input[
                                len("share file ") :
                            ].split()
                        except ValueError:
                            console.print(
                                "[bold red]Invalid input. Please use format:[/bold red] [blue]share file <filename> <username>[/blue]"
                            )
                            continue
                        
                    console.print(f"Sharing [green]{file_to_share}[/green] with [green]{share_with}[/green]")
                    file_to_share = sanitize_filename(file_to_share)
                    
                    with console.status(f"[bold green]Sharing file with {share_with}...[/bold green]"):
                        try:
                            result = share_file(
                                file_to_share,
                                share_with,
                                unique_id,
                                username,
                                user_key,
                            )
                            if result is True:
                                console.print(f"[bold green]Successfully shared {file_to_share} with {share_with}[/bold green]")
                        except Exception as e:
                            console.print(f"[bold red]Failed to share file: {str(e)}[/bold red]")
                            logger.debug(f"Exception details: {e}", exc_info=True)
                            
                # Handle get shared command (6 or get shared...)
                elif user_input == "6" or user_input.startswith("get shared "):
                    if user_input == "6":
                        filename = Prompt.ask("[bold blue]Enter shared filename to get[/bold blue]")
                    else:
                        filename = user_input[len("get shared ") :].strip()
                        
                    filename = sanitize_filename(filename)
                    logger.debug(f"get shared: {filename}")
                    
                    with console.status(f"[bold green]Getting shared file {filename}...[/bold green]"):
                        try:
                            get_shared_file(filename, unique_id, user_key)
                        except Exception as e:
                            console.print(f"[bold red]Failed to get shared file: {str(e)}[/bold red]")
                            logger.debug(f"Exception details: {e}", exc_info=True)
                            
                # Handle remove user command (7 or remove user)
                elif user_input == "7" or user_input == "remove user":
                    if Confirm.ask("[bold red]Are you sure you want to remove your account? This cannot be undone.[/bold red]"):
                        with console.status("[bold yellow]Removing user account...[/bold yellow]"):
                            remove_user(
                                username, unique_id, USERPATH, user_master_key=user_key
                            )
                        console.print("[bold yellow]User removed. Logging out.[/bold yellow]")
                        break
                    else:
                        console.print("[green]Account removal cancelled.[/green]")
                        
                else:
                    console.print("[bold red]Invalid command. Please try again.[/bold red]")
                    console.print("Use numbers 1-8 or the full command names shown in the menu.")
                    
                # Add a separator between commands for better readability
                console.print("─" * console.width)
                
        else:
            console.print("[bold red]Authentication failed.[/bold red]")

    else:
        console.print("[bold red]Invalid action.[/bold red] Use [green]register[/green] or [green]login[/green].")

    console.print("[bold blue]Done.[/bold blue]")


if __name__ == "__main__":
    main()
