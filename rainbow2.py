import hashlib
import pyfiglet


def hash_sha256(password):
    pass_hash = hashlib.sha256(f"{password}".encode('utf-8'))
    hashed = pass_hash.hexdigest()
    return hashed

def reduce_hash(hash, password_length):#password_length : entier indiquant la longueur de la sous-chaîne souhaitée.
    return hash[:password_length]#la syntaxe de slicing de Python pour obtenir la sous chaine de longeur password_length

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
def main():
    
    dictionary = load_dictionary('my_dict.txt')
    rainbow_table = generate_rainbow_table_from_dictionary(dictionary)
    # test 
    user_input = input("Enter a Password or Hash  : ")
    if len(user_input) == 64:#Un hachage SHA-256 typique est une chaîne hexadécimale de 64 caractères
        try:
            password =  hash_to_password(user_input, rainbow_table)
            if hash_sha256(password) == user_input:
                print("password is : "+password+"  Password trouve dans la table ")
            else:
                print("Password not found")
        except KeyError:
            print("Password not found")
    else:#si l'etulisateur a entrer un mot de passe
        hash = generate_chain(user_input, 1000, 8)
        print("Hash is : "+hash)
        try:
            print("Password trouve dans la table : "+rainbow_table[hash])
        except KeyError:
            print("Password not found")
            
if __name__ == '__main__':
    ascii_banner = pyfiglet.figlet_format("NAILA \n RAINBOW Attack simulator")
    print(ascii_banner)
    main()