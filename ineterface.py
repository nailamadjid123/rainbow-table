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




def brute_force_attack():
    # Code pour l'attaque brute force
    print("Exécution de l'attaque brute force")


def rainbow_attack():
    print("Exécution de l'attaque par rainbow table")
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


def dictionary_attack():
    # Code pour l'attaque par dictionnaire
    print("Exécution de l'attaque par dictionnaire")

def main():
    # Création de la fenêtre principale
    root = tk.Tk()
    root.title("Sélecteur de méthode d'attaque")

    # Création et disposition des widgets
    label = tk.Label(root, text="Choisissez une méthode d'attaque :")
    label.pack(pady=10)

    button_brute_force = tk.Button(root, text="Attaque brute force", command=brute_force_attack)
    button_brute_force.pack(pady=5)

    button_rainbow = tk.Button(root, text="Attaque par rainbow table", command=rainbow_attack)
    button_rainbow.pack(pady=5)

    button_dictionary = tk.Button(root, text="Attaque par dictionnaire", command=dictionary_attack)
    button_dictionary.pack(pady=5)

    # Boucle principale
    root.mainloop()

if __name__ == "__main__":
    main()
