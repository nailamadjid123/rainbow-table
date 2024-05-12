import hashlib
import tkinter as tk

def brute_force_attack():
    # Insérer ici le code pour exécuter la méthode d'attaque brute force
    print("Attaque brute force")

def rainbow_attack():
    # Insérer ici le code pour exécuter la méthode d'attaque par rainbow table
   import hashlib


def hash_sha256(password):
    pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))

    hashed = pass_hash.hexdigest()
    return hashed

def generate_rainbow_table(dictionary, chain_length=1000):
    
    rainbow_table = {}
    for password in dictionary:
        current_hash = hash_sha256(password)
       
        rainbow_table[current_hash] = password
        
    return rainbow_table

def reduce_function(hashcode):
    candidate_password = ""

    for i in range(8):
        candidate_password += hashcode[i]

    return candidate_password


def generate_rainbow_table_from_dictionary(dictionary, chain_length=1000):
    
    rainbow_table = {}
    for password in dictionary:
        current_hash = hash_sha256(password)
        for _ in range(chain_length):
            rainbow_table[current_hash] = password
    return rainbow_table

def load_dictionary(filename):
    """Charge un dictionnaire de mots de passe depuis un fichier texte."""
    with open(filename, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file]
    
    
    # Fonction principale
def main():
    # Charger le dictionnaire
    dictionary = load_dictionary("my_dict.txt")
    
    # Générer la table arc-en-ciel
    rainbow_table = generate_rainbow_table_from_dictionary(dictionary)
    
    # Demander à l'utilisateur de saisir un mot de passe ou son hachage
    user_input = input("Entrez un mot de passe ou son hachage : ")
    chain_length=1000
    # Vérifier si l'entrée est un hachage ou un mot de passe
    if len(user_input) == 64:  # Longueur typique d'un hachage SHA-256
        hashed_password = user_input
        # Appliquer la réduction directement sur le hachage fourni
        hashed_password = user_input
       

        for _ in range(chain_length):
            current_hash = hash_sha256(reduce_function(hashed_password))
            if current_hash in rainbow_table:
                original_password = rainbow_table[current_hash]
                print("Mot de passe trouvé après réduction et hachage :")
                print("Mot de passe original :", original_password)
                break
        else:
            print("Le mot de passe n'a pas été trouvé après 1000 itérations de réduction et de hachage.")
    else:
        hashed_password = hash_sha256(user_input)
        # Vérifier si le hachage est dans la table arc-en-ciel
        if hashed_password in rainbow_table:
            original_password = rainbow_table[hashed_password]
            if hash_sha256(original_password) == hashed_password:
                print("Mot de passe trouvé dans la table arc-en-ciel :")
                print("Mot de passe original :", original_password)
            else:
                print("Faux positif détecté : le mot de passe trouvé ne correspond pas au hachage fourni.")
        else:
            print("Mot de passe non trouvé dans la table arc-en-ciel.")

# Appeler la fonction principale si ce script est exécuté
if __name__ == "__main__":
    main()

    print("Attaque par rainbow table")

def dictionary_attack():
    # Insérer ici le code pour exécuter la méthode d'attaque par dictionnaire
    print("Attaque par dictionnaire")

root = tk.Tk()
root.title("Sélecteur de méthode d'attaque")

label = tk.Label(root, text="Choisissez une méthode d'attaque :")
label.pack()

button_brute_force = tk.Button(root, text="Attaque brute force", command=brute_force_attack)
button_brute_force.pack()

button_rainbow = tk.Button(root, text="Attaque par rainbow table", command=rainbow_attack)
button_rainbow.pack()

button_dictionary = tk.Button(root, text="Attaque par dictionnaire", command=dictionary_attack)
button_dictionary.pack()

root.mainloop()
