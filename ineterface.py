import tkinter as tk
from tkinter import messagebox, filedialog,Toplevel
import hashlib
import time

def brute_force(password_hash, hash_method, max_length, output_file, salt=None):
    characters = string.ascii_letters + string.digits + string.punctuation

    with open(output_file, 'a') as f:
        for length in range(1, max_length + 1):
            for combination in itertools.product(characters, repeat=length):
                password_attempt = ''.join(combination)
                
                # Ajouter le sel si nécessaire
                salted_password = password_attempt
                if salt:
                    if password_hash.startswith(salt):
                        salted_password = salt + password_attempt
                    elif password_hash.endswith(salt):
                        salted_password = password_attempt + salt
                
                if hash_method == 'md5':
                    hashed_attempt = hashlib.md5(salted_password.encode()).hexdigest()
                elif hash_method == 'sha256':
                    hashed_attempt = hashlib.sha256(salted_password.encode()).hexdigest()
                else:
                    messagebox.showerror("Error", "Invalid hash method.")
                    return None
                
                if hashed_attempt == password_hash:
                    result = f"[+] Password Found: {password_attempt}\n"
                    f.write(password_attempt + '\n')  # Écriture du mot de passe trouvé dans le fichier
                    return password_attempt

    return None