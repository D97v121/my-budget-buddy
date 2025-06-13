# encryption_utils.py
from cryptography.fernet import Fernet
import os


ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable is missing!")

f = Fernet(ENCRYPTION_KEY.encode())  # Convert to bytes

def encrypt_data(data):
    return f.encrypt(data.encode()).decode()

def decrypt_data(data):
    return f.decrypt(data.encode()).decode()  # T