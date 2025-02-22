import os
import unittest
from unittest.mock import mock_open, patch

# Update this import to match your project structure
from src.utils.utils import store_file_metadata


class TestStoreEncryptedFek(unittest.TestCase):
    def setUp(self):
        self.test_fek = b"test_encrypted_fek"
        self.test_salt = b"test_salt"
        self.test_filename = "testfile"
        self.test_metadata_path = "/test/metadata"

    def tearDown(self):
        # Clean up if metadata folder exists
        if os.path.exists(self.test_metadata_path):
            import shutil

            shutil.rmtree(self.test_metadata_path)

    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_store_file_metadata_creates_directory(
        self, mock_file, mock_makedirs, mock_exists
    ):
        # Configure mocks
        mock_exists.return_value = False

        with patch("src.utils.utils.METADATA_FOLDER", self.test_metadata_path):
            store_file_metadata(
                self.test_fek, self.test_filename, self.test_salt
            )

            # Verify directory creation
            mock_makedirs.assert_called_once_with(
                self.test_metadata_path, exist_ok=True
            )
            mock_file.assert_called_once()

    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("builtins.open")
    def test_store_file_metadata_file_not_found(
        self, mock_open, mock_makedirs, mock_exists
    ):
        mock_exists.return_value = True
        mock_open.side_effect = FileNotFoundError

        with patch("src.utils.utils.METADATA_FOLDER", self.test_metadata_path):
            with self.assertRaises(FileNotFoundError):
                store_file_metadata(
                    self.test_fek, self.test_filename, self.test_salt
                )

    @patch("os.path.exists")
    @patch("os.makedirs")
    def test_store_file_metadata_permission_denied(
        self, mock_makedirs, mock_exists
    ):
        mock_exists.return_value = False
        mock_makedirs.side_effect = PermissionError

        with patch("src.utils.utils.METADATA_FOLDER", self.test_metadata_path):
            with self.assertRaises(PermissionError):
                store_file_metadata(
                    self.test_fek, self.test_filename, self.test_salt
                )


if __name__ == "__main__":
    unittest.main()
