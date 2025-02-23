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


## client-tui

* Provides a nice user interface with:

* A main menu screen
 
* A login screen
 
* A registration screen
 
* A logged-in screen
 
* Includes keyboard shortcuts:
 
* Ctrl+Q to quit
 
* Ctrl+L to open login screen
 
* Ctrl+R to open registration screen
 
* Escape to go back/logout

