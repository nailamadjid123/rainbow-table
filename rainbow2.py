import hashlib
import random
import string

import time

# Fonction de hachage SHA-256

def hash_sha256(password):
    pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))#.encode('utf-8') convertit une chaîne Unicode en une séquence d'octets encodée en UTF-8.

    hashed = pass_hash.hexdigest()
    return hashed

hashed_password = hash_sha256("test")
print(hashed_password)


                                              #******************************************************#


def reduce_function(hashcode):
    # Choisissez un certain nombre de caractères du hachage pour former le mot de passe candidat
    password_length = 8  # Définissez la longueur du mot de passe candidat
    candidate_password = ""
    for char in hashcode:
        # Ajoutez chaque caractère du hachage au mot de passe candidat
        candidate_password += char
        # Arrêtez de construire le mot de passe candidat lorsque sa longueur atteint la longueur souhaitée
        if len(candidate_password) >= password_length:
            break
    return candidate_password
                                               #******************************************************#

def generate_chain(password, chain_length):
    """Génère une chaîne arc-en-ciel à partir d'un mot de passe."""
    hashcode = hash_sha256(password)
    for _ in range(chain_length):
        hashcode = hash_sha256(reduce_function(hashcode))
    return hashcode
                                     #*****************************************************#
 
 
def generate_rainbow_table_from_dictionary(dictionary, chain_length=1000):
    """Génère une table arc-en-ciel à partir d'un dictionnaire de mots de passe."""
    rainbow_table = {}
    for password in dictionary:
        current_hash = hash_sha256(password)
        for _ in range(chain_length):
            current_hash = hash_sha256(reduce_function(current_hash))
        rainbow_table[current_hash] = password
    return rainbow_table

                                                  #*****************************************************#
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
        current_hash = hashed_password
        for _ in range(chain_length):
            current_hash = hash_sha256(reduce_function(current_hash))
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
