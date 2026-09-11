import sys
import os

# Project root
project_root = os.path.dirname(os.path.abspath(__file__))

# Backend directory
backend_dir = os.path.join(project_root, "backend")

# Add backend to Python path
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import Flask app
from backend.app import app