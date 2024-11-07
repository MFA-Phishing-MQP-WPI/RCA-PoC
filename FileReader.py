import os
from typing import Optional, Union

class FR:
    @staticmethod
    def read(file_path: str, mode: str = 'rb') -> Optional[Union[bytes, str]]:
        """Reads the content of a file. Returns None if file does not exist."""
        try:
            with open(file_path, mode) as f:
                return f.read()
        except FileNotFoundError:
            return None

    @staticmethod
    def write(file_path: str, content: Union[str, bytes], mode: str = 'wb') -> None:
        """Writes content to a file, creating directories if they do not exist."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, mode) as f:
            f.write(content)

    class path:
        @staticmethod
        def exists(file_path: str) -> bool:
            """Checks if a file exists at the specified path."""
            return os.path.exists(file_path)
        @staticmethod
        def create(file_path: str) -> None:
            """Creates a file path at the specified path."""
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
