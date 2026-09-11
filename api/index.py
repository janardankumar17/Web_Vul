import sys
import os

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(__file__))

# Get the backend directory
backend_dir = os.path.join(project_root, "backend")

# Add both directories to Python's import path
sys.path.insert(0, project_root)
sys.path.insert(0, backend_dir)

# Import Flask app
from backend.app import app