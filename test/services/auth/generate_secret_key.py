import bcrypt
import secrets
import os
import json

SECRET_KEY_FILE = 'secret_key.json'

def generate_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        print("Secret key file already exists. No new key generated.")
        return

    secret_key = secrets.token_hex(32)  # Generates a random 32-byte hex string

    hashed_key = bcrypt.hashpw(secret_key.encode('utf-8'), bcrypt.gensalt())

    with open(SECRET_KEY_FILE, 'w') as f:
        json.dump({
            "hashed_key": hashed_key.decode('utf-8')
        }, f)

    print("Secret key generated and saved to secret_key.json")

if __name__ == "__main__":
    generate_secret_key()