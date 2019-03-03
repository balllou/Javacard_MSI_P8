from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from smartcard.System import readers
from logging.handlers import RotatingFileHandler
import os
import logging
import ecdsa
import random
import subprocess
import binascii

compteurparticipant = 0
verr = False
logger = logging.getLogger()
init = False
affiche = 0


def hex_to_str(value_hex):
    string_value = bytearray.fromhex(value_hex).decode()
    return string_value


def list_int_to_hex(list_in):
    stringhex = ""
    for i in list_in:
        stringhex += hex(i)
    stringstring = hex_to_str(stringhex[2:])
    return stringstring


def init_carte(name, surname):
    global compteurparticipant, logger
    name = name+" "
    surname = surname+" "
    namehex = name.encode("UTF-8").hex()
    while len(namehex) < 24:
        namehex = "0" + namehex

    surnamehex = surname.encode("UTF-8").hex()
    while len(surnamehex) < 24:
        surnamehex = "0"+surnamehex

    compteur_participant_hex = "{:x}".format(compteurparticipant)
    while len(compteur_participant_hex) < 10:
        compteur_participant_hex = "0" + compteur_participant_hex
    pin = generatepin()
    print("Voici le PIN du Client: " + str(pin))
    pinhex = "{:x}".format(pin)
    while len(str(pinhex)) < 4:
        pinhex="0"+pinhex
    # Génération de la pair de clés ECDSA pour signer la carte
    clesecrete = ecdsa.SigningKey.generate(
        curve=ecdsa.SECP256k1)  # Géneration clé secrete carte
    clesecrete_string = (clesecrete.to_string()).hex()
    clepublic = clesecrete.get_verifying_key()  # Génération clé publique carte
    clepubcarte_string = (clepublic.to_string()).hex()
    message = namehex+surnamehex+str(compteurparticipant)  # données a signer
    signdata = clesecrete.sign(message.encode("utf-8"))  # Exemple signature message
    print("Secret:" + str(signdata))
    file_ = open("secretpubliccarte", 'w')
    file_.write(clepubcarte_string + "\n")
    file_.close()
    print("pinhex : " + str(pinhex))
    print ("surnamehex : " + surnamehex)
    print ("namehex : " + namehex)
    print ("num participant hex : "+ compteur_participant_hex)
    print ("signature : " + str(binascii.hexlify(signdata)))
    print (len(str(binascii.hexlify(signdata))))
    print(len(pinhex+surnamehex+namehex+compteur_participant_hex+str(binascii.hexlify(signdata))))

    reponse = subprocess.check_output(['java', '-jar', '/home/grs/JavaCard/GlobalPlatformPro/gp.jar', '-install',
                                       '../Festival304.cap', '--param', pinhex+surnamehex+namehex+compteur_participant_hex+str(binascii.hexlify(signdata))])
    
    
    if reponse.startswith("No smart"):
        logger.DEBUG(
            "Fournisseur de carte--- Echec d'initialisation de la carte")
        return False
    else:
        logger.DEBUG("Fournisseur de carte--- Carte initialisée")
        compteurparticipant += 1
        return signdata


def connexion(r):
    global logger
    connection = r[0].createConnection()
    connection.connect()
    logger.debug("Fournisseur de carte--- Connexion sur la carte")
    logger.setLevel(logging.DEBUG)
    # logger.setLevel(logging.RELEASE)
    formatter = logging.Formatter(
        '%(asctime)s :: %(levelname)s :: %(message)s')
    file_handler = RotatingFileHandler('installation.log', 'a', 1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.debug("Fournisseur de carte --- Connexion de la carte")


def deconnexion():
    global logger
    logger.DEBUG("Fournisseur de carte --- Déconnexion de la carte")
    connection.disconnect()


def lock_cart(key):
    global verr, logger
    logger.DEBUG("Fournisseur de carte --- Demande de vérouillage de la carte")
    reponse = subprocess.check_output(
        ['java', '-jar', '/home/grs/JavaCard/GlobalPlatformPro/gp.jar', '-lock', key])
    print('returned value:', reponse)
    verr = True


def unlock_card(key):
    global verr, logger
    logger.DEBUG(
        "Fournisseur de carte --- Demande de dévérouillage de la carte")
    reponse = subprocess.check_output(
        ['java', '-jar', '/home/grs/JavaCard/GlobalPlatformPro/gp.jar', '-key', key, '-unlock'])
    print('returned value:', reponse)
    verr = False


def generatepin():
    global logger
    logger.debug("Fournisseur de carte--- Génération d'un nouveau PIN")
    pin0 = random.randint(0, 9)
    pin1 = random.randint(0, 9)
    pin2 = random.randint(0, 9)
    pin3 = random.randint(0, 9)
    pin = str(pin0)+str(pin1)+str(pin2)+str(pin3)
    pin = int(pin)
    logger.debug("Fournisseur de carte--- Nouveau Pin généré")
    return pin


# Main
while True:
    r = readers()
    if r == []:
        if affiche == 0:
            print("Bonjour veuillez insérer une carte afin de l'initialiser\n")
            affiche += 1
    else:
        while r != []:
            print("Carte détécter\n")
            affiche = 0
            connexion(r)
            if verr == True:
                print("Carte vérouillée")
            else:
                choix = input(
                    "Quelle opération voulez vous effectuer: \n 1- Initialiser une carte\n 2-Verrouiller une carte\n 3- Dévérouiller une carte\n 4-Se deconnecter\n")
                if choix == "1":
                    print("Initialisation de la carte suivez les instructions\n")
                    nom = input("Entrez le nom du participant\n")
                    prenom = input("Entrez le prenom du participant\n")
                    signdata = init_carte(nom, prenom)
                    init = True
                if choix == "2":
                    print("Demande de vérouillage de la carte\n")
                    if verr == True:
                        print("Carte déjà vérouillée\n")
                    else:
                        if init == True:
                            lock_cart(signdata)
                        else:
                            secret = input(
                                "Rentrer le secret afin de de vérouiller la carte\n")
                            lock_cart(secret)
                if choix == "3":
                    if verr == False:
                        print("Carte déjà dévérouillée\n")
                    else:
                        if init == True:
                            unlock_card(signdata)
                        else:
                            secret = input(
                                "Rentrer le secret afin de dévérouiller la carte")
                            lock_cart(secret)
                if choix == "4":
                    deconnexion()
                    print("Carte déconnectée\n")
                    init = False
