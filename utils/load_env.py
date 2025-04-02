import os
from dotenv import load_dotenv

def load_environment():
    """Load .env from the project root directory."""
    root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    env_path = os.path.join(root_path, ".env")
    load_dotenv(env_path)