import sqlite3

import bcrypt
from cryptography.fernet import Fernet

key = Fernet.generate_key()
salt = bcrypt.gensalt()
fernet = Fernet(key)


def crypt_password(password):
    coderMessage = fernet.encrypt(password.encode())
    return coderMessage


# cod = crypt_password("bonjour")

def decrypt_password(password):
    decMessage = fernet.decrypt(password).decode()
    return decMessage


def hashUserPassword(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return str(hashed)


def checkHashUserPassword(password, hashed):
    print(password, hashed)
    if bcrypt.checkpw(password.encode('utf-8'), hashed):
        return True
    else:
        return False


def insert_list_password(liste):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "INSERT INTO PASSWORD (url, username, mdp, description) VALUES (?,?,?,?)"

        cur.executemany(sql, liste)
        conn.commit()
        print("Enregistrements insérés avec succès dans la table PASSWORD")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de l'insertion dans la table PASSWORD", error)

liste = [('bonjour', 'coléoptère', 'illuminati', '3456134677'),
         ('5364636', 'FDGERH', 'fdhgfgjfgh', 'dfhgfgh'),
         ('5346457245724', 'GDFGDHF', 'fghdfgh', 'fghfghfggj')]


## Inserer une ligne dans la table PASSWORD
def insert_one_password(url, username, mdp, description):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "INSERT INTO PASSWORD (url, username, mdp, description) VALUES ('{0}','{1}','{2}','{3}')".format(url,
                                                                                   username, mdp, description)

        cur.execute(sql)
        conn.commit()
        print("Enregistrements insérés avec succès dans la table PASSWORD")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de l'insertion dans la table PASSWORD", error)




# insert_liste_password(liste)

def insert_user(username, password):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "INSERT INTO USER (username, password) VALUES ('{0}',\"{1}\")".format(username,
                                                                                    hashUserPassword(password))

        cur.execute(sql)
        conn.commit()
        print("Enregistrements insérés avec succès dans la table USER")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de l'insertion dans la table PASSWORD", error)


insert_user('juju34', 'lemusclé')

# ## Supprime une ligne de la table USER
def delete_user(username):
    conn = sqlite3.connect('dbpass.db')
    cur = conn.cursor()
    print("Connexion réussie à SQLite")

    sql = "DELETE FROM USER WHERE username = {0}".format(username)

    cur.execute(sql)
    conn.commit()
    print("suppression validée dans la table USER")
    cur.close()
    conn.close()
    print("Connexion SQLite est fermée")

# ## Met à jour une ligne de la table USER
def update_user(username, password):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "UPDATE USER " \
              "SET password ='{0}' WHERE username={1}" \
            .format(newPassword, newUsername)

        cur.execute(sql)
        conn.commit()
        print("changement validée dans la colonne mdp de la table USER")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors lors de la mise à jour dans la colonne mdp", error)
"""
    Récupérer le mot de passe à partir d'une URL
"""


def get_password_from_db(id):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "SELECT mdp FROM PASSWORD WHERE id={0}".format(id)
        print(sql)

        cur.execute(sql)
        print("récupération validée depuis la colonne mdp de la table PASSWORD")
        print(cur.fetchone())
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de la récupération dans la colonne mdp", error)


# get_password_from_db(2)

def delete_password_from_db(id):
    conn = sqlite3.connect('dbpass.db')
    cur = conn.cursor()
    print("Connexion réussie à SQLite")

    sql = "DELETE FROM PASSWORD WHERE id = {0}".format(id)

    cur.execute(sql)
    conn.commit()
    print("suppression validée dans la table PASSWORD")
    cur.close()
    conn.close()
    print("Connexion SQLite est fermée")


# delete_password_from_db(3)
def update_password_from_db(id, newPassword, newUsername, newDescription, newUrl):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "UPDATE PASSWORD " \
              "SET mdp ='{0}',username = '{1}', description = '{2}', url = '{3}' WHERE id={4}" \
            .format(newPassword, newUsername, newDescription, newUrl, id)

        cur.execute(sql)
        conn.commit()
        print("changement validée dans la colonne mdp de la table PASSWORD")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors lors de la mise à jour dans la colonne mdp", error)


# update_password_from_db(2, 'nzonzi', 'username', 'description', 'url')
def get_all_from_db():
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()
        print("Connexion réussie à SQLite")

        sql = "SELECT * FROM PASSWORD"

        cur.execute(sql)
        print(cur.fetchall())
        print("récupération de toute les données effectué depuis la table PASSWORD")
        cur.close()
        conn.close()
        print("Connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de la récupération des données de la table PASSWORD", error)


# get_all_from_db()
def crypt_password(password):
    coderMessage = fernet.encrypt(password.encode())
    print(coderMessage)
    return coderMessage


# cod = crypt_password("bonjour")

def decrypt_password(password):
    decMessage = fernet.decrypt(password).decode()
    print(decMessage)
    return decMessage


# decrypt_password(cod)

def generate_password(length, letters, numerics, symbols):
#     """
# :param length: longueur mdp INTEGER
# :param letters: mdp contient des lettres BOOLEAN
# :param numerics: mdp contient des chiffres BOOLEAN \
# :param symbols: mdp contient des symboles BOOLEAN
# :return: mdp aléatoire
#     """
    list_password_to_generate = []
    if letters == True:
        letters_list = list(string.ascii_lowercase) + list(string.ascii_upercase)
        list_password_to_generate = list_password_to_generate + letters_list
        print(letters_list)
    elif numerics == True:
        numerics_list = ['0','1','2','3','4','5','6','7','8','9']
        list_password_to_generate = list_password_to_generate + numerics_list
        print(numerics_list)
    elif symbols == True: 
        symbols_list = ['@','&','#','£','^','|','~','-','\\','_','/','?','!','%','$','€','µ','*','§']
        list_password_to_generate = list_password_to_generate + symbols_list
        print(symbols_list)   

def estConnuDansLaDB(username, password):
    try:
        conn = sqlite3.connect('dbpass.db')
        cur = conn.cursor()

        sql = "Select password FROM USER WHERE username = '{0}'".format(username)

        cur.execute(sql)

        result = cur.fetchone()[0]
        print(result)

        cur.close()
        conn.close()
        return checkHashUserPassword(password, result)

    except sqlite3.Error as error:
        print("Erreur lors de la récupération dans la colonne mdp", error)


print(estConnuDansLaDB('juju34', 'lemusclé'))
