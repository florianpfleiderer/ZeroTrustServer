import datetime
import os
import base64
from typing import Any, Optional
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding

USERPATH = Path("data/client/users").resolve()
CA_PATH = Path("data/certificates").resolve()
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"
CERT_PATH = Path("data/server/certificates").resolve()


def encrypt_user_register(
    user_register: dict, user_id: str, cipher=None
) -> bytes:
    """Encrypt the user register.

    Args:
    ----
        user_register (dict): the user register
        user_id (str): the user id

    Returns:
    -------
        bytes: the encrypted user register
    """
    if cipher:
        return cipher.encrypt(json.dumps(user_register).encode())
    else:
        raise ValueError("Cipher must be provided")


def decrypt_user_register(
    encrypted_key: bytes, encrypted_register: bytes, user_id: str
) -> bytes:
    """Decrypt the user register.

    Args:
    ----
        encrypted_key (bytes): the encrypted key
        user_id (str): the user id

    Returns:
    -------
        bytes: the decrypted key
    """
    # decrypt the symmetric key with the user private key
    user_private_key: rsa.RSAPrivateKey = load_key_from_disk(
        USERPATH / user_id, f"{user_id}.pem"
    )
    original_sym_key = user_private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    cipher = Fernet(original_sym_key)
    # decrypt the user register
    return json.loads(cipher.decrypt(encrypted_register)), cipher


def generate_private_key() -> rsa.RSAPrivateKey:
    """Genrates a private x509 key.

    Returns
    -------
        : _description_
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def serialise_certificate(cert: x509.Certificate) -> bytes:
    """Serialise the certificate to bytes.

    Args:
    ----
        cert (x509.Certificate): the certificate

    Returns:
    -------
        bytes: the serialised certificate
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def unserialize_certificate(cert: bytes) -> x509.Certificate:
    """Unserialise the certificate from bytes.

    Args:
    ----
        cert (bytes): the serialised certificate

    Returns:
    -------
        x509.Certificate: the certificate
    """
    return x509.load_pem_x509_certificate(cert.encode("utf-8"))


def generate_csr(
    private_key: Any, name: str = "default", email: Optional[str] = None
) -> x509.Certificate:
    """Generates a Certificate Signing Request (CSR) with the given private key.

    Args:
    ----
        privatekey (RSAPrivateKey): the user private key
        name (str, optional): Defaults to "default".
        email (str, optional): Defaults to None.

    Returns:
    -------
        x509.Certificate: the user signed certificate
    """
    user_subject = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]
    )
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(user_subject)
        .sign(private_key, hashes.SHA256())
    )


def sign_certificate_request(
    csr: x509.CertificateSigningRequest,
    ca_key: Any,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    """Signs the certificate signing request with the CA key.

    Args:
    ----
        csr (x509.CertificateSigningRequest): the certificate signing request
        ca_key (RSAPrivateKey): the CA private key

    Returns:
    -------
        x509.Certificate: the signed certificate
    """
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365)
        )
    ).sign(private_key=ca_key, algorithm=hashes.SHA256())


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """Verify the public certificate with the CA certificate."""
    # cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_cert = load_cert_from_disk(CA_PATH)
    # ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        # ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    except Exception as e:
        print(e)
        return False
    return True


def save_key_to_disk(
    key: Any, path: str, filename: str = "private_key.pem"
) -> None:
    """Save the private key to disk.

    Args:
    ----
        key (): the private key
        path (str): path directory where the file should go
        filename (str, optional):the name of the file. Defaults to "private_key.pem".
    """
    filepath: str = os.path.join(path, os.path.basename(filename))
    with open(filepath, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def load_key_from_disk(
    path: str, filename: str = "private_key.pem"
) -> rsa.RSAPrivateKey:
    """Load the private key from disk.

    Args:
    ----
        path (str): the path to the file (without filename)
        filename (str, optional): the name of the file. Defaults to "private_key.pem".

    Returns:
    -------
        : the private key
    """
    filepath: str = os.path.join(path, os.path.basename(filename))
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def save_cert_to_disk(
    cert: x509.Certificate, path: str, filename: str = "certificate.pem"
) -> None:
    """Save the certificate to disk.

    Args:
    ----
        cert (x509.Certificate): the certificate
        path (str): the path to the folder
        filename (str, optional): the name of the file. Defaults to "certificate.pem".
    """
    filepath: str = os.path.join(path, os.path.basename(filename))
    with open(filepath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert_from_disk(
    path: str, filename: str = "ca_certificate.pem"
) -> x509.Certificate:
    """Load the certificate from disk.

    Args:
    ----
        path (str): the path to the file
        filename (str, optional): the name of the file. Defaults to "certificate.pem".
    """
    filepath: str = os.path.join(path, os.path.basename(filename))
    with open(filepath, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def generate_server_certificate() -> None:
    """Generate server key and certificate if they don't exist."""
    server_key = CERT_PATH / "server_key.pem"
    server_cert = CERT_PATH / "server_cert.pem"
    server_csr = CERT_PATH / "server.csr.pem"
    config_file = CERT_PATH / "configuration.cnf"
    ca_cert = CA_PATH / "ca_certificate.pem"
    ca_key = CA_PATH / "ca_private_key.pem"

    if not server_key.exists() or not server_cert.exists():
        print("Generating server key and certificate...")
        # Generate server key
        subprocess.run(
            ["/usr/bin/openssl", "genrsa", "-out", server_key, "2048"],
            check=True,
        )

        # Generate CSR
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-new",
                "-key",
                server_key,
                "-out",
                server_csr,
                "-config",
                config_file,
            ],
            check=True,
        )

        # Sign CSR with CA
        subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-req",
                "-in",
                server_csr,
                "-CA",
                ca_cert,
                "-CAkey",
                ca_key,
                "-CAcreateserial",
                "-out",
                server_cert,
                "-days",
                "3650",
                "-sha256",
                "-extfile",
                config_file,
                "-extensions",
                "req_ext",
            ],
            check=True,
        )

        # Remove CSR after signing
        server_csr.unlink()
        print("Server certificate generated and signed.")
    else:
        print("Server key and certificate already exist.")
