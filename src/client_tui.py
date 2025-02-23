from __future__ import annotations

import getpass
import logging
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Header, Input, Label, Static, Footer
from textual.binding import Binding

from client import register_user, authenticate_user, get_user_id, get_user_master_key, USERPATH

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LoginScreen(Screen):
    """Login screen for the application."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Header(show_clock=True),
            Container(
                Label("Username:"),
                Input(id="username", placeholder="Enter username"),
                Label("Password:"),
                Input(id="password", password=True, placeholder="Enter password"),
                Horizontal(
                    Button("Login", variant="primary", id="login"),
                    Button("Cancel", variant="error", id="cancel"),
                ),
                id="login-container",
            ),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login":
            username = self.query_one("#username").value
            password = self.query_one("#password").value
            
            if authenticate_user(username, password, USERPATH):
                unique_id = get_user_id(username, USERPATH)
                userfile_path = USERPATH / unique_id / f"{unique_id}.json"
                user_key = get_user_master_key(userfile_path, username, password)
                logger.info("Welcome %s!", username)
                self.app.push_screen("logged_in", username=username)
            else:
                self.notify("Authentication failed", severity="error")
        elif event.button.id == "cancel":
            self.app.pop_screen()

class RegisterScreen(Screen):
    """Registration screen for new users."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Header(show_clock=True),
            Container(
                Label("Username:"),
                Input(id="username", placeholder="Enter username"),
                Label("Password:"),
                Input(id="password", password=True, placeholder="Enter password"),
                Horizontal(
                    Button("Register", variant="primary", id="register"),
                    Button("Cancel", variant="error", id="cancel"),
                ),
                id="register-container",
            ),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "register":
            username = self.query_one("#username").value
            password = self.query_one("#password").value
            
            register_user(username, password, USERPATH)
            self.notify("Registration complete", severity="information")
            self.app.pop_screen()
        elif event.button.id == "cancel":
            self.app.pop_screen()

class LoggedInScreen(Screen):
    """Screen shown after successful login."""

    BINDINGS = [
        Binding("escape", "logout", "Logout", show=True),
    ]

    def __init__(self, username: str) -> None:
        super().__init__()
        self.username = username

    def compose(self) -> ComposeResult:
        yield Container(
            Header(show_clock=True),
            Static(f"Welcome, {self.username}!"),
            Button("Logout", variant="error", id="logout"),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "logout":
            self.action_logout()

    def action_logout(self) -> None:
        self.app.pop_screen()
        self.notify("Logged out successfully", severity="information")

class ClientTUI(App):
    """The main TUI application."""

    CSS = """
    Screen {
        align: center middle;
    }

    #login-container, #register-container {
        width: 40;
        height: auto;
        border: solid green;
        padding: 1;
    }

    Button {
        margin: 1;
    }

    Label {
        margin-top: 1;
    }

    Input {
        margin-bottom: 1;
    }
    """

    SCREENS = {
        "login": LoginScreen,
        "register": RegisterScreen,
        "logged_in": LoggedInScreen,
    }

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+l", "push_screen('login')", "Login", show=True),
        Binding("ctrl+r", "push_screen('register')", "Register", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Container(
            Header(show_clock=True),
            Container(
                Button("Login", variant="primary", id="login"),
                Button("Register", variant="success", id="register"),
                Button("Quit", variant="error", id="quit"),
            ),
            Footer(),
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login":
            self.push_screen("login")
        elif event.button.id == "register":
            self.push_screen("register")
        elif event.button.id == "quit":
            self.exit()

def main():
    app = ClientTUI()
    app.run()

if __name__ == "__main__":
    main() 