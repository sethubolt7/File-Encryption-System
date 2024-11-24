# File-Encryption-System

This is a Python-based file encryption and decryption tool with a user-friendly graphical interface built using Tkinter. It enables users to securely encrypt files, send the decryption key via email, and decrypt files using the provided key. The encryption process leverages the `cryptography` library, where files are encrypted with a generated key. To enhance security, the key itself is encrypted with a passphrase-derived key using PBKDF2 before being saved. 

The tool includes email integration, allowing the decryption key to be sent automatically to a specified recipient via SMTP with SSL. Decryption verifies the provided key to restore the original file content securely. With its simple GUI, users can easily select files, input email addresses, and perform encryption or decryption operations. This tool is ideal for securely sharing files, ensuring that only authorized recipients can access the original content.
