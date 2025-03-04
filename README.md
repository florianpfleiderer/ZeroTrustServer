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

`>share file frog.jpg <registered-user>`

`>logout`

`client login <registered-user>`

`show files` will show "shared files: ..."

`get shared frog` the file will be in data/client/downloaded_files

## Rich CLI Interface

The application now includes an improved command-line interface using the Rich library for better visual feedback and user experience. Features include:

- Colorful and styled output
- Progress bars for file operations
- Tables for displaying users and files
- Interactive prompts and confirmations
- Better error messages with appropriate styling
- Numbered menu options for quicker command selection

To use the improved CLI, make sure to install the required dependencies:

```bash
pip install -e .
```

Or install Rich directly:

```bash
pip install rich==13.7.1
```

Then run the client as usual:

```bash
python src/client.py register <username>
# or
python src/client.py login <username>
```

### Quick Command Reference

Once logged in, you can use either the full command or just the number:

1. `upload <filename>` - Upload a file to the server
2. `download <filename>` - Download a file from the server 
3. `show users` - Show all registered users
4. `show files` - Show your files and files shared with you
5. `share file <filename> <username>` - Share a file with another user
6. `get shared <filename>` - Get a file shared with you
7. `remove user` - Delete your account
8. `logout` - Exit the application

When using numbers (e.g., typing `1` instead of `upload <filename>`), you'll be prompted for any additional information needed.

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
