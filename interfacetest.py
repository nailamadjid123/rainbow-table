import tkinter as tk
from tkinter import Toplevel, messagebox, filedialog
import hashlib
import time
import os
import string
import itertools
from PIL import Image,ImageTk



# Fonction pour attaquer par dictionnaire
def dictionary_attack_window():
    def process():
        def hash_md5(password):
            pass_hash = hashlib.md5(f"{password}".encode('utf-8'))
            hashed = pass_hash.hexdigest()
            return hashed

        def hash_sha256(password):
            pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))
            hashed = pass_hash.hexdigest()
            return hashed

        def hash_sha512(password):
            pass_hash = hashlib.sha512(f"{password}".encode('utf-8'))
            hashed = pass_hash.hexdigest()
            return hashed

        def crack_hash(hash_value, hash_method):
            attempts = 0
            found = False
            start_time = time.time()

            with open(r'my_dict.txt') as pass_file:
                for word in pass_file:
                    word = word.strip()
                    if hash_method == "md5":
                        digest = hashlib.md5(word.encode('utf-8')).hexdigest()
                    elif hash_method == "sha256":
                        digest = hashlib.sha256(word.encode('utf-8')).hexdigest()
                    elif hash_method == "sha512":
                        digest = hashlib.sha512(word.encode('utf-8')).hexdigest()
                    else:
                        messagebox.showerror("Erreur", "Méthode de hachage non supportée")
                        return

                    attempts += 1
                    if digest == hash_value:
                        found = True
                        messagebox.showinfo("Résultat", f"Mot de passe trouvé : {word}")
                        messagebox.showinfo("Informations", f"Nombre total de tentatives pour casser le hachage : {attempts}")
                        break

            end_time = time.time()
            elapsed_time = end_time - start_time

            if not found:
                messagebox.showinfo("Temps écoulé", f"Temps écoulé : {elapsed_time} secondes")
                messagebox.showinfo("Informations", f"Aucun mot de passe trouvé. Nombre total de tentatives : {attempts}")

        hash_value = hash_entry.get()
        hash_method = hash_method_var.get()
        crack_hash(hash_value, hash_method)

    new_window = Toplevel()
    new_window.title("Attaque par dictionnaire")

    tk.Label(new_window, text="Entrez le hash à cracker :").pack(pady=10)
    hash_entry = tk.Entry(new_window, width=50)
    hash_entry.pack(pady=5)

    hash_method_var = tk.StringVar(value="md5")
    tk.Label(new_window, text="Sélectionnez la méthode de hachage :").pack(pady=5)
    tk.Radiobutton(new_window, text="MD5", variable=hash_method_var, value="md5").pack()
    tk.Radiobutton(new_window, text="SHA-256", variable=hash_method_var, value="sha256").pack()
    tk.Radiobutton(new_window, text="SHA-512", variable=hash_method_var, value="sha512").pack()

    tk.Button(new_window, text="Exécuter l'attaque", command=process, width=20, height=2).pack(pady=10)

# fonction d'interface brute force
def brute_force(password_hash, hash_method, max_length, output_file, salt=None):
    characters = string.ascii_letters + string.digits + string.punctuation

    with open(output_file, 'a') as f:
        for length in range(1, max_length + 1):
            for combination in itertools.product(characters, repeat=length):
                password_attempt = ''.join(combination)
                if salt:
                    if password_hash.startswith(salt):
                        password_hash = password_hash.removeprefix(salt)
                    elif password_hash.endswith(salt):
                        password_hash = password_hash.removesuffix(salt)

                if hash_method == 'md5':
                    hashed_attempt = hashlib.md5(password_attempt.encode()).hexdigest()
                elif hash_method == 'sha256':
                    hashed_attempt = hashlib.sha256(password_attempt.encode()).hexdigest()
                else:
                    messagebox.showerror("Error", "Invalid hash method.")
                    return None
                
                if hashed_attempt == password_hash:
                    result = f"[+] Password Found: {password_attempt}\n"
                    f.write(password_attempt + '\n')  # Écriture du mot de passe trouvé dans le fichier
                    return password_attempt

    return None
def brute_force_attack_window():
    def browse_file(entry):
        filename = filedialog.askopenfilename()
        entry.delete(0, tk.END)
        entry.insert(0, filename)

    def process():
        password_hash = hash_entry.get()
        hash_method = method_var.get()
        max_length = int(length_entry.get())
        output_file = output_entry.get()
        salt = salt_entry.get()

        if not os.access(output_file, os.W_OK):
            messagebox.showerror("Erreur", "Vous n'avez pas la permission d'écrire dans ce fichier.")
            return

        found_password = brute_force(password_hash, hash_method, max_length, output_file, salt)
        if found_password:
            messagebox.showinfo("Success", "Password found and saved to file.")
        else:
            messagebox.showinfo("Failure", "Password not found.")

    new_window = Toplevel()
    new_window.title("Brute Force Attack")

    # Header
    header_label = tk.Label(new_window, text="BRUTE FORCE", font=("Helvetica", 18), background="#f0f0f0")
    header_label.pack(pady=10)

    # Frame pour les options
    options_frame = tk.Frame(new_window)
    options_frame.pack(pady=10)

    # Entrée du hash
    hash_label = tk.Label(options_frame, text="Password Hash:")
    hash_label.grid(row=0, column=0, padx=5, pady=5)
    hash_entry = tk.Entry(options_frame)
    hash_entry.grid(row=0, column=1, padx=5, pady=5)

    # Méthode de hachage
    method_var = tk.StringVar()
    method_var.set("md5")
    method_label = tk.Label(options_frame, text="Hash Method:")
    method_label.grid(row=1, column=0, padx=5, pady=5)
    method_menu = tk.OptionMenu(options_frame, method_var, "md5", "sha256")
    method_menu.grid(row=1, column=1, padx=5, pady=5)

    # Longueur maximale du mot de passe
    length_label = tk.Label(options_frame, text="Max Password Length:")
    length_label.grid(row=2, column=0, padx=5, pady=5)
    length_entry = tk.Entry(options_frame)
    length_entry.grid(row=2, column=1, padx=5, pady=5)

    # Fichier de sortie
    output_label = tk.Label(options_frame, text="Output File:")
    output_label.grid(row=3, column=0, padx=5, pady=5)
    output_entry = tk.Entry(options_frame)
    output_entry.grid(row=3, column=1, padx=5, pady=5)
    output_button = tk.Button(options_frame, text="Browse", command=lambda: browse_file(output_entry))
    output_button.grid(row=3, column=2, padx=5, pady=5)

    # Salt
    salt_label = tk.Label(options_frame, text="Salt (if used):")
    salt_label.grid(row=4, column=0, padx=5, pady=5)
    salt_entry = tk.Entry(options_frame)
    salt_entry.grid(row=4, column=1, padx=5, pady=5)

    # Bouton de traitement
    process_button = tk.Button(new_window, text="Crack Password", command=process)
    process_button.pack(pady=10)

# Fonction pour attaquer avec Rainbow Table (non modifiée)
def rainbow_attack_window():
    def perform_rainbow_attack():
        password = entry_input.get()
        if not password:
            messagebox.showwarning("Entrée", "Veuillez entrer un mot de passe ou un hachage.")
            return

        try:
            dictionary = load_dictionary("my_dict.txt")
            rainbow_table = generate_rainbow_table_from_dictionary(dictionary)
            
            result_text = ""
            if len(password) == 64:  # Longueur typique d'un hachage SHA-256
                try:
                    found_password = hash_to_password(password, rainbow_table)
                    if hash_sha256(found_password) == password:
                        result_text = f"Mot de passe trouvé : {found_password}"
                    else:
                        result_text = "Mot de passe non trouvé"
                except KeyError:
                    result_text = "Mot de passe non trouvé"
            else:
                generated_hash = generate_chain(password, 1000, 8)
                result_text = f"Hash généré : {generated_hash}\n"
                try:
                    found_password = rainbow_table[generated_hash]
                    result_text += f"Mot de passe trouvé dans la table : {found_password}"
                except KeyError:
                    result_text += "Mot de passe non trouvé"

            result_label.config(text=result_text)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'attaque par table arc-en-ciel: {e}")

    new_window = Toplevel()
    new_window.title("Rainbow Table Attack")

    tk.Label(new_window, text="Entrez un mot de passe ou un hachage :").pack(pady=10)
    entry_input = tk.Entry(new_window, width=50)
    entry_input.pack(pady=5)

    tk.Button(new_window, text="Exécuter l'attaque", command=perform_rainbow_attack, width=20, height=2).pack(pady=10)
    result_label = tk.Label(new_window, text="")
    result_label.pack(pady=10)

# Fonctions utilitaires pour le hachage et les tables arc-en-ciel
def hash_sha256(password):
    pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))
    hashed = pass_hash.hexdigest()
    return hashed

def reduce_hash(hash, password_length):
    return hash[:password_length]

def generate_chain(password, chain_length, password_length):
    hash = hash_sha256(password)
    for _ in range(chain_length):
        password = reduce_hash(hash, password_length)
        hash = hash_sha256(password)
    return hash

def generate_rainbow_table_from_dictionary(dictionary):
    rainbow_table = {}
    chain_length = 1000
    password_length = 8
    for password in dictionary:
        hash = generate_chain(password, chain_length, password_length)
        rainbow_table[hash] = password
    return rainbow_table

def load_dictionary(file_path):
    with open(file_path, 'r') as file:
        dictionary = file.read().splitlines()
    return dictionary

def hash_to_password(hash, rainbow_table):
    chain_length = 1000
    for _ in range(chain_length):
        hash = reduce_hash(hash, 8)
        hash = hash_sha256(hash)
    return rainbow_table[hash]

# Fonction principale de l'interface
def main():
    # Création de la fenêtre principale
    root = tk.Tk()
    root.geometry("600x400") 
    root.config(bg="black")
    root.title("Sélecteur de méthode d'attaque")
    
    # Création et disposition des widgets
    label = tk.Label(root, text="Choisissez une méthode d'attaque :", font="Bahnschrift 20", bg="#100E30", fg="#E91E63")
    label.pack(pady=10)

    button_brute_force = tk.Button(root, text="Attaque brute force", command=brute_force_attack_window, width=20, height=2, font="BahnschrifLight 13", takefocus=0, bg="#100E30", fg="#9C27B0", activebackground="#100E38", activeforeground="#9C27B0", bd=0, highlightthickness=0)
    button_brute_force.pack(pady=5)

    button_rainbow = tk.Button(root, text="Attaque par rainbow table", command=rainbow_attack_window, width=20, height=2, activebackground="#100E38", font="BahnschrifLight 13", takefocus=0, bg="#100E30", fg="#3F51Bf", activeforeground="#3F51Bf", bd=0, highlightthickness=0)
    button_rainbow.pack(pady=5)

    button_dictionary = tk.Button(root, text="Attaque par dictionnaire", command=dictionary_attack_window, width=20, height=2, activebackground="#100E38", font="BahnschrifLight 13", takefocus=0, bg="#100E30", fg="#00BCD4", activeforeground="#00BCD4", bd=0, highlightthickness=0)
    button_dictionary.pack(pady=5)

    # Exécution de la boucle principale
    root.mainloop()

if __name__ == "__main__":
    main()

