# wsgi.py
from dotenv import load_dotenv
from pathlib import Path

# Load the project-root .env explicitly
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

from app import create_app
app = create_app()

if __name__ == "__main__":
    app.run()
