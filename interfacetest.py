import tkinter as tk
import hashlib

# Fonction pour hacher avec SHA-256
def hash_sha256(password):
    pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))
    hashed = pass_hash.hexdigest()
    return hashed

# Fonction pour générer une table arc-en-ciel à partir d'un dictionnaire
def generate_rainbow_table_from_dictionary(dictionary, chain_length=1000):
    rainbow_table = {}
    for password in dictionary:
        current_hash = hash_sha256(password)
        for _ in range(chain_length):
            rainbow_table[current_hash] = password
    return rainbow_table

# Fonction pour charger un dictionnaire depuis un fichier texte
def load_dictionary(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file]

# Fonction de réduction (simplifiée pour l'exemple)
def reduce_function(hashcode):
    candidate_password = ""
    for i in range(8):
        candidate_password += hashcode[i]
    return candidate_password

# Fonction pour exécuter l'attaque de table arc-en-ciel
def rainbow_attack():
    try:
        # Charger le dictionnaire
        dictionary = load_dictionary("my_dict.txt")
        
        # Générer la table arc-en-ciel
        rainbow_table = generate_rainbow_table_from_dictionary(dictionary)
        
        # Demander à l'utilisateur de saisir un mot de passe ou son hachage
        user_input = input("Entrez un mot de passe ou son hachage : ")
        chain_length = 1000
        
        if len(user_input) == 64:  # Longueur typique d'un hachage SHA-256
            hashed_password = user_input
            for _ in range(chain_length):
                current_hash = hash_sha256(reduce_function(hashed_password))
                if current_hash in rainbow_table:
                    original_password = rainbow_table[current_hash]
                    print("Mot de passe trouvé après réduction et hachage :")
                    print("Mot de passe original :", original_password)
                    break
                hashed_password = hash_sha256(reduce_function(hashed_password))
            else:
                print("Le mot de passe n'a pas été trouvé après 1000 itérations de réduction et de hachage.")
        else:
            hashed_password = hash_sha256(user_input)
            if hashed_password in rainbow_table:
                original_password = rainbow_table[hashed_password]
                if hash_sha256(original_password) == hashed_password:
                    print("Mot de passe trouvé dans la table arc-en-ciel :")
                    print("Mot de passe original :", original_password)
                else:
                    print("Faux positif détecté : le mot de passe trouvé ne correspond pas au hachage fourni.")
            else:
                print("Mot de passe non trouvé dans la table arc-en-ciel.")
    except Exception as e:
        print(f"Erreur lors de l'attaque par table arc-en-ciel: {e}")

# Fonction pour exécuter l'attaque brute force (exemple)
def brute_force_attack():
    print("Exécution de l'attaque brute force")

# Fonction pour exécuter l'attaque par dictionnaire (exemple)
def dictionary_attack():
    print("Exécution de l'attaque par dictionnaire")

# Création de la fenêtre principale
root = tk.Tk()
root.title("Sélecteur de méthode d'attaque")
# Variables associées aux Checkbuttons
var_brute_force = tk.BooleanVar()
var_rainbow = tk.BooleanVar()
var_dictionary = tk.BooleanVar()

# Création et disposition des widgets
label = tk.Label(root, text="Choisissez les méthodes d'attaque :")
label.pack(pady=10)

checkbutton_brute_force = tk.Checkbutton(root, text="Attaque brute force", variable=var_brute_force)
checkbutton_brute_force.pack(pady=5)

checkbutton_rainbow = tk.Checkbutton(root, text="Attaque par rainbow table", variable=var_rainbow)
checkbutton_rainbow.pack(pady=5)

checkbutton_dictionary = tk.Checkbutton(root, text="Attaque par dictionnaire", variable=var_dictionary)
checkbutton_dictionary.pack(pady=5)

execute_button = tk.Button(root, text="Exécuter", command=execute_selected_methods)
execute_button.pack(pady=10)



# Fonction pour exécuter les méthodes sélectionnées
def execute_selected_methods():
    if var_brute_force.get():
        brute_force_attack()
    if var_rainbow.get():
        rainbow_attack()
    if var_dictionary.get():
        dictionary_attack()

# Boucle principale
root.mainloop()
