# infos

port = last 5 digits of matriculation number (30614)

## setup

`python3 -m venv venv`

`pip install --upgrade pip`

Install: `pip install -e .`

Install with optional dependencies: `pip install -e ".[dev]"`

## example usage

`server`

Open new terminal:

`client register <name>`

Enter password & random mail (no email sent). 2Fa Code will be in `data/server/users/<uuid>/2fa_code.txt`. Enter code to complete registration.

`client login <name>`

`>upload frog.jpg`

`>share file frog.jpg user1`

`>logout`

`client login othername`

`show files` will show "shared files: ..."

`get shared frog` the file will be in data/client/downloaded_files


## done

1. enhance key management
    - generate a unique FEK (file encryption key)
    - derive master key from user ['generate_key'](src/utils/utils.py#L15)
    - encrypt FEK using master key
    - store encrypted FEK and Salt
    - decrypt: retrieve encrypted FEK, salt and decrypt using master key
2. introduce multiple users
3. implement mTLS for secure connection to server
4. change fek procedure so that the metadata is stored per user (knowledge of which files thave been uploaded)
5. sign all uploaded data with private key (access control through public key)
6. enable 2FA using flask mailman (mailman setup complete)
7. implement file sharing mechanisms
    - retrieve registered users, select user to share the file with, encrypt using his public key
    - how does the server notify the registered user of a new file for him (the server needs to connect filename and user_id still)
    - what happens to unique feks in this case? if I still use them, how is the fek shared with the other user? -> SOLUTION: a keys file with encrypted feks for the userfile, if a new user registers...see overleaf
