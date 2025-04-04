import sys
import os

# Add your project directory to the sys.path
sys.path.insert(0, os.path.dirname(__file__))

from app import app as application  # Replace 'app' with your Flask app filename if different
