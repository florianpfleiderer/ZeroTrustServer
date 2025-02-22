import hashlib
import json
import logging
import os
from pprint import pprint
from typing import Any, Optional
from xmlrpc.client import boolean

import bcrypt

logger = logging.getLogger(__name__)


def get_user_id(username: str, path: str) -> str:
    """Retrieves the user ID from the directory.

    Args:
    ----
        path (str): path to the client/users/ directory

    Returns:
    -------
        str: the unique user ID
    """
    try:
        with open(os.path.join(path, "users.json")) as f:
            users = json.load(f)
            for user in users:
                if user["username"] == username:
                    return user["unique_id"]
    except FileNotFoundError:
        user_id = ""
        logger.error("File not found: %s", os.path.join(path, "users.json"))
    return user_id


def check_existing_user(username: str, path: str) -> bool:
    """Checks if the user is already registered.

    Args:
    ----
        username (str): The username to check.
        path (str): Path to the client/users/ directory.

    Returns:
    -------
        bool: True if the user is already registered, False otherwise.
    """
    users_file = os.path.join(path, "users.json")

    # Initialize users.json with an empty list if it doesn't exist
    if not os.path.exists(users_file):
        try:
            with open(users_file, "w") as f:
                json.dump([], f)
            return False
        except Exception as e:
            logger.error("Error initializing %s: %s", users_file, e)
            return False

    try:
        with open(users_file) as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                # If JSON is malformed, reset it to an empty list
                print(
                    f"Malformed JSON in {users_file}. Resetting to empty list."
                )
                logger.warning(
                    "Malformed JSON in %s. Resetting to empty list.", users_file
                )
                users = []
                with open(users_file, "w") as fw:
                    json.dump(users, fw)

            # Ensure that users is a list
            if not isinstance(users, list):
                print(
                    f"Unexpected JSON structure in {users_file}. Resetting to empty list."
                )
                logger.warning(
                    "Unexpected JSON structure in %s. Resetting to empty list.",
                    users_file,
                )
                users = []
                with open(users_file, "w") as fw:
                    json.dump(users, fw)
                return False

            # Check if any user has the matching username
            for user in users:
                if isinstance(user, dict) and user.get("username") == username:
                    return True

    except FileNotFoundError:
        # File doesn't exist; should have been created above, but handle just in case
        print(f"{users_file} not found. Creating a new one.")
        logger.error("%s not found. Creating a new one.", users_file)
        try:
            with open(users_file, "w") as f:
                json.dump([], f)
        except Exception as e:
            print(f"Error creating {users_file}: {e}")
            logger.error("Error creating %s: %s", users_file, e)
        return False
    except Exception as e:
        # Handle other unexpected exceptions
        print(f"An unexpected error occurred while checking user: {e}")
        logger.error("An unexpected error occurred while checking user: %s", e)
        return False

    # If user not found
    return False


def add_user_to_register(username: str, user_id: str, path: str) -> boolean:
    """Updates the users.json file with the new user data.

    Args:
    ----
        username (str): random username
        user_id (str): unique user ID
        path (str): path to the client/users/ directory
    """
    path = os.path.join(path, "users.json")
    try:
        with open(path) as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = []

    for user in users:
        if user["username"] == username:
            return False
    users.append({"username": username, "unique_id": user_id})

    with open(path, "w") as f:
        json.dump(users, f, indent=4)
    return True


def remove_user_from_register(username: str, path: str) -> boolean:
    """Removes the user from the users.json file.

    Args:
    ----
        username (str): random username
        path (str): path to the client/users/ directory
    """
    path = os.path.join(path, "users.json")
    try:
        with open(path) as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return False

    for user in users:
        if user["username"] == username:
            users.remove(user)
            with open(path, "w") as f:
                json.dump(users, f, indent=4)
            return True
    return False


def register_client_user(
    username: str, password: str, path: str, unique_id: str
) -> None:
    """Registers a user with the system.

    Args:
    ----
        username (str): random username
        password (str): the user password
        path (str): path to the client/users/ directory
        unique_id (str): unique user ID
    """
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_data = {
        "username": username,
        "password_hash": password_hash.decode("utf-8"),
        "unique_id": unique_id,
        "salt": os.urandom(16).hex(),
    }
    # salt = os.urandom(16)
    # user_data["salt"] = salt.hex()

    # TODO: encrypt the data
    filepath = os.path.join(path, f"{os.path.basename(unique_id)}.json")

    with open(filepath, "w") as f:
        json.dump(user_data, f, indent=4)


def authenticate_user(username: str, password: str, path: str) -> bool:
    """Authenticates a user by verifying their password.

    Args:
    ----
        username (str): The username of the user.
        password (str): The password provided by the user.
        path (str): The absolute path to the users directory.

    Returns:
    -------
        bool: True if authentication is successful, False otherwise.
    """
    users_file_path = os.path.join(path, "users.json")
    user_id = None

    try:
        with open(users_file_path) as f:
            users = json.load(f)
    except FileNotFoundError:
        logger.error("Users file not found at %s.", users_file_path)
        return False
    except json.JSONDecodeError:
        logger.error("Malformed JSON in %s.", users_file_path)
        return False
    except Exception as e:
        logger.error(
            "Unexpected error while reading %s: %s", users_file_path, e
        )
        return False

    # Search for the user in the users list
    for user_data in users:
        if user_data.get("username") == username:
            user_id = user_data.get("unique_id")
            break

    if not user_id:
        print(f"Username '{username}' not found.")
        return False

    # Path to the user's JSON file containing the password hash
    user_json_path = os.path.join(
        path, os.path.basename(user_id), f"{os.path.basename(user_id)}.json"
    )

    try:
        with open(user_json_path) as userfile:
            # Parse the user's JSON data
            user_data = json.load(userfile)

        # Retrieve the password hash
        password_hash = user_data.get("password_hash")
        if not password_hash:
            logger.error("No password_hash found for user '%s'.", username)
            return False

        # Verify the password
        if bcrypt.checkpw(password.encode(), password_hash.encode("utf-8")):
            logger.debug("User '%s' authenticated successfully.", username)
            return True
        else:
            logger.warning("Incorrect password for user '%s'.", username)
            return False

    except FileNotFoundError:
        logger.error("User JSON file not found at %s.", user_json_path)
        return False
    except json.JSONDecodeError:
        logger.error("Malformed JSON in %s.", user_json_path)
        return False
    except Exception as e:
        logger.error("Unexpected error while reading %s: %s", user_json_path, e)
        return False


def get_user_master_key(
    path: str, username: str, password: Optional[str] = None
) -> bytes:
    user: dict[str, Any] = find_user(username, path)
    salt: bytes = bytes.fromhex(user["salt"])
    return hashlib.scrypt(
        password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32
    )


def find_user(username: str, path: str) -> dict[str, Any]:
    # check if path is directory or file
    if os.path.isdir(path):
        path = os.path.join(path, "users.json")
    with open(path) as f:
        users: list[dict[str, Any]] = json.load(f)

    if isinstance(users, dict):
        users = [users]
    for user in users:
        if user["username"] == username:
            return user
    return {}
