# Flask AES Image Encryption App

A simple Flask app for secure image uploads with AES encryption, user authentication, and shareable decryption links.

## Features
- User signup/login (passwords hashed)
- Upload images encrypted with AES-256 (CBC mode)
- Download/decrypt images with a shareable link and key
- SQLite database for users and uploads
- Bootstrap UI

## Setup

1. **Clone the repo and install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2. **Run the app:**
    ```bash
    python app.py
    ```

3. **Visit:**
    - Home: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)

## Usage
- Sign up and log in
- Upload an image (get a decryption key and shareable link)
- Share the link and key to allow others to decrypt/download the image
- View/delete your uploads in "My Uploads"

## Notes
- The AES key is shown only once after upload. Save it!
- Encrypted files are stored in `/uploads`.
- The app uses Flask-Login, Flask-SQLAlchemy, and PyCryptodome.

## Security
- Passwords are hashed (Werkzeug)
- AES-256 in CBC mode with random IV
- Key is never stored on the server

---

MIT License 