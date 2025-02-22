import json
import unittest
from unittest import TestCase
from unittest.mock import patch

from src.utils.users import find_user


class TestFindUser(TestCase):
    def setUp(self):
        # Sample JSON data for different test scenarios
        self.multiple_users_data = json.dumps(
            [
                {"username": "user1", "unique_id": "e8vx6"},
                {"username": "user2", "unique_id": "f7vy9"},
            ]
        )
        self.single_user_data = json.dumps(
            {"username": "test", "unique_id": "0d53fa"}
        )
        self.empty_users_data = json.dumps([])

    @patch("os.path.isdir")
    @patch("builtins.open")
    def test_find_user_in_directory(self, mock_open_file, mock_isdir):
        # Configure mocks
        mock_isdir.return_value = False
        mock_open_file.return_value.__enter__.return_value.read.return_value = (
            self.multiple_users_data
        )

        result = find_user("user1", "/users/users.json")
        self.assertEqual(result["username"], "user1")
        self.assertEqual(result["unique_id"], "e8vx6")
        mock_open_file.assert_called_once_with("/users/users.json")

    @patch("os.path.isdir")
    @patch("builtins.open")
    def test_find_user_if_1_user(self, mock_open_file, mock_isdir):
        # Configure mocks
        mock_isdir.return_value = False
        mock_open_file.return_value.__enter__.return_value.read.return_value = (
            self.single_user_data
        )

        result = find_user("test", "/users/single_user.json")
        self.assertEqual(result, {"username": "test", "unique_id": "0d53fa"})
        mock_open_file.assert_called_once_with("/users/single_user.json")

    @patch("os.path.isdir")
    @patch("builtins.open")
    def test_user_not_found(self, mock_open_file, mock_isdir):
        # Configure mocks
        mock_isdir.return_value = False
        mock_open_file.return_value.__enter__.return_value.read.return_value = (
            self.multiple_users_data
        )

        result = find_user("nonexistentuser", "users/users.json")
        self.assertEqual(result, {})
        mock_open_file.assert_called_once_with("users/users.json")

    @patch("os.path.isdir")
    @patch("builtins.open")
    def test_file_not_found(self, mock_open_file, mock_isdir):
        mock_isdir.return_value = False
        mock_open_file.side_effect = FileNotFoundError

        with self.assertRaises(FileNotFoundError):
            find_user("testuser", "/users/path/users.json")


if __name__ == "__main__":
    unittest.main()
