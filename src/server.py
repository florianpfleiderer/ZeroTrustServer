import base64
import json
import os
import shutil
import ssl
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, jsonify, request, send_from_directory
from flask_mailman import Mail, EmailMessage
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import NotFound
from werkzeug.utils import secure_filename

from utils.certificates import (
    generate_server_certificate,
    save_cert_to_disk,
    unserialize_certificate,
)

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Configure mail settings
app.config["MAIL_SERVER"] = "smtp.sendgrid.net"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "apikey" 
app.config["MAIL_PASSWORD"] = (
    "placeholder"
)
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_DEFAULT_SENDER"] = "online.user@mailbox.org"
# Initialize the Mail object
mail = Mail(app)

MAILMAN_API_TOKEN = os.getenv("MAILMAN_API", "9%iKT16yV8$nzT")
API_TOKEN = os.getenv("API_TOKEN", "MYSECRETTOKEN")
UPLOAD_FOLDER = Path("data/server/uploaded_files").resolve()
CA_PATH = Path("data/certificates").resolve()
USER_PATH = Path("data/server/users").resolve()
CERT_PATH = Path("data/server/certificates").resolve()

if not UPLOAD_FOLDER.exists():
    UPLOAD_FOLDER.mkdir(parents=True)


@app.route("/send_email", methods=["POST"])
def send_email() -> jsonify:
    mail = EmailMessage(
        subject="Test Email",
        body="This is a test email from the server.",
        to=["recipient@domain.org"],
    )
    mail.send()
    return jsonify({"message": "Email sent successfully"}), 200


@app.route("/register", methods=["POST"])
def register_user() -> jsonify:
    """Receives a POST request with user_id and certificate sign reqest to
    register the user.

    Returns
    -------
        json: success or error message
    """
    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    username = data.get("username")
    user_id = data.get("user_id")
    user_mail = data.get("email")
    certificate = data.get("certificate")
    try:
        certificate = unserialize_certificate(certificate)
    except Exception as e:
        return jsonify({"message": f"Invalid CSR format: {e}"}), 400

    if not user_id or not certificate:
        return jsonify({"message": "User ID and Certificate required"}), 400

    # Generate 2FA code
    two_factor_code = secrets.randbelow(999999)

    # Send 2FA code via email
    # email_subject = "Your 2FA Code"
    # email_body = f"Your 2FA code is: {two_factor_code}"
    # email_recipient = [user_mail]

    # msg = EmailMessage(
    #     subject=email_subject,
    #     body=email_body,
    #     to=email_recipient,
    # )
    # try:
    #     msg.send()
    # except Exception:
    #     app.logger.exception("Failed to send email")
    #     return jsonify({"message": "Failed to send 2FA code via email"}), 500

    # create user dircectory
    user_dir = USER_PATH / user_id
    if user_dir.exists():
        return jsonify({"message": "User already registered"}), 402
    user_dir.mkdir(parents=True)
    # save signed user certificate to disk
    save_cert_to_disk(certificate, user_dir, f"{user_id}.pem")

    # Save 2FA code to file
    with Path(user_dir / "2fa_code.txt").open("w") as f:
        f.write(str(two_factor_code))

    return jsonify(
        {"message": "Waiting for 2FA code to verify user registration"}
    ), 200


@app.route("/verify", methods=["POST"])
def verify_mfa() -> jsonify:
    """Receives a POST request with user_id and certificate sign reqest to
    register the user.

    Returns
    -------
        json: success or error message
    """
    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    username = data.get("username")
    user_id = data.get("user_id")
    mfa_code = data.get("mfa")
    certificate = data.get("certificate")
    try:
        certificate = unserialize_certificate(certificate)
    except Exception as e:
        return jsonify({"message": f"Invalid CSR format: {e}"}), 400

    if not user_id or not certificate:
        return jsonify({"message": "User ID and Certificate required"}), 400

    # Verify 2FA code
    with Path(USER_PATH / user_id / "2fa_code.txt").open("r") as f:
        stored_code = f.read()
    Path(USER_PATH / user_id / "2fa_code.txt").unlink()
    if mfa_code != stored_code:
        if Path(USER_PATH / user_id).exists():
            shutil.rmtree(USER_PATH / user_id)
        return jsonify({"message": "Invalid 2FA code"}), 600

    # add user id and corresponding filenames to json register
    new_user_data = {"user_id": user_id, "username": username}

    user_keys = USER_PATH / "keys.json"
    if not user_keys.exists():
        with Path(user_keys).open("w") as f:
            json.dump({}, f)

    with Path(user_keys).open("r") as f:
        keys = json.load(f)
    if keys:
        # user is not the first user
        # NOTE: the following section should be a request to an existing user
        # to retrieve his symmetric key, decrypt it and encrypt it with the new
        # user's public key
        existing_user_id = next(iter(keys.keys()))
        with (
            Path("data/client/users")
            .joinpath(existing_user_id, f"{existing_user_id}.pem")
            .resolve()
            .open("rb") as f
        ):
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        # retrive the encrypted key
        enc_key = keys[existing_user_id]
        # Decrypt the data
        original_sym_key = private_key.decrypt(
            base64.b64decode(enc_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        cipher = Fernet(original_sym_key)
        with Path(USER_PATH / "enc.meta").open("rb") as f:
            encrypted_user_register = f.read()
        # decrypt the user data with the symmetric key
        decrypted_user_register = json.loads(
            cipher.decrypt(encrypted_user_register)
        )
        # add the new user data to the register
        if isinstance(decrypted_user_register, dict):
            decrypted_user_register = [decrypted_user_register]
        decrypted_user_register.append(new_user_data)
        # encrypt the register with the original symmetric key
        encrypted_user_register = cipher.encrypt(
            json.dumps(decrypted_user_register).encode()
        )
        with Path(USER_PATH / "enc.meta").open("wb") as f:
            f.write(encrypted_user_register)
        # encrypt the symmetric key with the new user's public key
        enc_sym_key = certificate.public_key().encrypt(
            original_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        keys[user_id] = base64.b64encode(enc_sym_key).decode("utf-8")
    else:
        # user is the first user
        keys = {}
        sym_key = Fernet.generate_key()
        # encrypt new user data with the symmetric key
        cipher = Fernet(sym_key)
        encrypted_user_register = cipher.encrypt(
            json.dumps(new_user_data).encode()
        )
        with Path(USER_PATH / "enc.meta").open("wb") as f:
            f.write(encrypted_user_register)
        # encrypt the symmetric key with the new user's public key
        enc_sym_key = certificate.public_key().encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        enc_sym_key = base64.b64encode(enc_sym_key).decode("utf-8")
        keys[user_id] = enc_sym_key
    with Path(USER_PATH / "keys.json").open("w") as f:
        json.dump(keys, f)

    return jsonify({"message": "User registered successfully"}), 200


@app.route("/get_user_register", methods=["GET"])
def get_user_register() -> jsonify:
    """Receives a GET request with user_id and retur.

    The keyfile will be saved the user's directory as enc.meta."""
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 401

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 402

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"message": "User ID required"}), 403

    enc_usr_path = USER_PATH / "enc.meta"

    if not enc_usr_path.exists():
        return jsonify({"message": "User not found on server"}), 201

    return send_from_directory(
        USER_PATH,
        "enc.meta",
        as_attachment=True,
        mimetype="application/octet-stream",
    )


@app.route("/get_user_key", methods=["GET"])
def get_user_key() -> jsonify:
    """Receives a GET request with user_id and returns the user's
    encrypted sym key.
    """
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 401

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 402

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"message": "User ID required"}), 403

    user_keys = USER_PATH / "keys.json"
    if not user_keys.exists():
        return jsonify({"message": "No users registered"}), 404
    with Path(user_keys).open("rb") as f:
        user_keys = json.load(f)
    enc_key = user_keys[user_id]
    return jsonify({"enc_key": enc_key}), 200


@app.route("/get_user_cert", methods=["GET"])
def get_user_cert() -> jsonify:
    """Receives a GET request with user_id and returns the user's certificate."""
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 401

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 402

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"message": "User ID required"}), 403

    user_cert = USER_PATH / user_id / f"{user_id}.pem"
    if not user_cert.exists():
        return jsonify({"message": "User not found on server"}), 404
    return send_from_directory(
        USER_PATH / user_id,
        f"{user_id}.pem",
        as_attachment=True,
        mimetype="application/octet-stream",
    )


@app.route("/remove", methods=["POST"])
def remove_user() -> jsonify:
    """Receives a POST request with user_id to remove the user.

    Returns
    -------
        json: success or error message
    """
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 401

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized to remove user"}), 402

    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"message": "User ID required"}), 403

    user_path = USER_PATH / user_id
    if not user_path.exists():
        return jsonify({"message": "User not found on server"}), 201
    # remove user directory
    for file in user_path.iterdir():
        file.unlink()
    user_path.rmdir()

    # remove user from keys.json
    with Path(USER_PATH / "keys.json").open("rb") as f:
        keys = json.load(f)
    keys.pop(user_id)
    with Path(USER_PATH / "keys.json").open("w") as f:
        json.dump(keys, f)
    # override user register with new file ()
    encrypted_user_register = request.files.get("user_register")
    if not encrypted_user_register:
        return jsonify({"message": "User register file is required"}), 400
    if encrypted_user_register:
        encrypted_user_register.save(USER_PATH / "enc.meta")

    filenames = request.form.get("filenames")
    print(filenames)
    filenames = json.loads(filenames) if filenames else []
    print(filenames)
    for filename in filenames:
        app.logger.info("Removing file: %s", filename)
        file_path = UPLOAD_FOLDER / filename
        if file_path.exists():
            file_path.unlink()
    return jsonify({"message": "User removed from server successfully"}), 200


@app.route("/upload", methods=["POST"])
def upload_file():
    """Accepts a POST request and stores the retrived data.

    Returns
    -------
        json: either success or error if no file provided
    """
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 403

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 401

    file = request.files.get("file")
    filename = secure_filename(file.filename)
    if file:
        file.save(UPLOAD_FOLDER / filename)
        return jsonify({"message": "File uploaded successfully"}), 200
    else:
        return jsonify({"message": "No file provided"}), 400


@app.route("/download/<filename>", methods=["GET"])
def download_file(filename: str) -> jsonify:
    """Accepts a GET request and provides the requested file.

    Args:
    ----
        filename (str): the name (random hash) of the file requested

    Returns:
    -------
        json: either success or error if no file provided
    """
    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 403

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 401

    try:
        file_path = UPLOAD_FOLDER / filename
        app.logger.debug("Looking for file at: %s", file_path)

        # Check if the file exists
        if not file_path.is_file():
            app.logger.error("File not found: %s", file_path)
            return jsonify({"message": "File not found"}), 404
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except (FileNotFoundError, NotFound) as e:
        app.logger.error("Error: %s", e)
        return jsonify({"message": "File not found"}), 404
    except Exception as e:
        app.logger.error("Error downloading file: %s", e)
        return jsonify({"message": "Internal Server Error"}), 500


@app.route("/share_file", methods=["POST"])
def share_file() -> jsonify:
    """Accepts a Post request with the updated user register."""

    client_cert = get_client_certificate()
    if not client_cert:
        return jsonify({"message": "Client certificate required"}), 403

    token = request.headers.get("Authorization")
    if token != API_TOKEN:
        return jsonify({"message": "Unauthorized"}), 401

    encrypted_user_register = request.files.get("user_register")
    if not encrypted_user_register:
        return jsonify({"message": "User register file is required"}), 400
    encrypted_user_register.save(USER_PATH / "enc.meta")

    return jsonify({"message": "User register updated successfully"}), 200


def get_client_certificate() -> x509.Certificate:
    """Retrieve and return the client's certificate if present."""
    cert_bin = request.environ.get("SSL_CLIENT_CERT")
    if not cert_bin:
        return None
    try:
        return x509.load_pem_x509_certificate(
            cert_bin.encode("utf-8"), default_backend()
        )
    except Exception:
        app.logger.exception("Error loading client certificate")
        return None


def main() -> None:
    """Spins up the server."""
    # checks if the server key and certificate exist
    # if not: generate and sign with CA
    generate_server_certificate()

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile="data/server/certificates/server_cert.pem",
        keyfile="data/server/certificates/server_key.pem",
    )
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="data/certificates/ca_certificate.pem")

    app.run(port=30614, debug=True, ssl_context=context)


if __name__ == "__main__":
    main()
