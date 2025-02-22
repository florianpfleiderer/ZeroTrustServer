"""Contains utility functions for making requests to the server."""

import os
from pathlib import Path
import requests
import logging

logger = logging.getLogger(__name__)

API_TOKEN = os.getenv("API_TOKEN", "MYSECRETTOKEN")
SERVER_URL = "https://localhost:30614"
USERPATH = Path("data/client/users").resolve()
CA_PATH = Path("data/certificates").resolve()
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"


def get_user_key(user_id: int) -> bytes:
    response = requests.get(
        f"{SERVER_URL}/get_user_key",
        json={"user_id": user_id},
        headers={"Authorization": API_TOKEN},
        cert=(
            USERPATH / user_id / f"{user_id}_cert.pem",
            USERPATH / user_id / f"{user_id}.pem",
        ),
        verify=CA_CERT_PATH,
        timeout=10,
    )
    response.raise_for_status()
    return response.json().get("enc_key")


def get_user_register(user_id: str) -> bytes:
    response = requests.get(
        f"{SERVER_URL}/get_user_register",
        json={"user_id": user_id},
        headers={"Authorization": API_TOKEN},
        cert=(
            USERPATH / user_id / f"{user_id}_cert.pem",
            USERPATH / user_id / f"{user_id}.pem",
        ),
        verify=CA_CERT_PATH,
        timeout=10,
    )
    return response.content


def get_user_cert(user_id: str) -> bytes:
    logger.debug(f"Getting user cert for user {user}")
    response = requests.get(
        f"{SERVER_URL}/get_user_cert",
        json={"user_id": user_id},
        headers={"Authorization": API_TOKEN},
        cert=(
            USERPATH / user_id / f"{user_id}_cert.pem",
            USERPATH / user_id / f"{user_id}.pem",
        ),
        verify=CA_CERT_PATH,
        timeout=10,
    )
    return response.content
