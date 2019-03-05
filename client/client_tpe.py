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
affiche = 0
import sys
logger = logging.getLogger()
from ecdsa import VerifyingKey, BadSignatureError
numparticipant=""

def hex_to_str(value_hex):
    string_value = bytearray.fromhex(value_hex).decode()
    return string_value


def list_int_to_hex(list_in):
    stringhex = ""
    for i in list_in:
        stringhex += hex(i)
    stringstring = hex_to_str(stringhex[2:])
    return stringstring


def connexion(r):
    global logger
    connection = r[0].createConnection()
    connection.connect()
   # logger.info("Fournisseur de carte--- Connexion sur la carte")
    logger.setLevel(logging.DEBUG)
    # logger.setLevel(logging.RELEASE)
    formatter = logging.Formatter(
        '%(asctime)s :: %(levelname)s :: %(message)s')
    file_handler = RotatingFileHandler('tpe.log', 'a', 1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    print("Connexion de la carte\n")
    data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
    #print(hex(sw1),hex(sw2))
    return connection


def deconnexion(connection):
    global logger
   # print("Déconnexion de la carte\n")
    connection.disconnect()


def decrement_credit(value):
    global numparticipant
    global logger
    print("Demande de payement d'une valeur de " +value + " en cours...\n")
    # sélection applet
    data, sw1, sw2 = connection.transmit(
        [0xB0, 0x05, 0x00, 0x00, 0x00, int(value)])
    #vk = VerifyingKey.from_pem(open("publicctpe.pem").read())
    #print(data)
    if data != []:
        montant= str((data[0]<<8)+data[1])
        print("Payement de "+value +
                          "crédits effectué il vous reste " + montant + " crédits\n")
        logger.info("TPE--- Participant numéro "+numparticipant +
                                "Payement effectué il vous reste " + montant + " crédits")
        return True
    else:
        print("Echec du paiement\n")
        logger.info("TPE--- Participant numéro"+numparticipant )
        return False
        # try:
        #     vk.verify(messagesign, message)
        #     print ("good signature")
        #     if (hex(sw1) == "0x90" and hex(sw2) == "0x00"):
        #         print("Payement de "+value +
        #                   "crédits effectué il vous reste" + montant + "crédits\n")
        #         logger.info("TPE--- Participant numéro"+numparticipant +
        #                         "Payement effectué il vous reste" + montant + "crédits")
        #         return True
        #     else:
        #         print("Echec du paiement\n")
        #         fichier.close()
        #         logger.info("TPE--- Participant numéro"+numparticipant +
        #                         " Echec du paiement d'un montant de"+montant)
        #         return False
        # except BadSignatureError:
        #     print ("mauvaise signature")       




def checkpin(pin, connection):
    global logger, numparticipant
    print("Vérification du code PIN en cours....\n")
    # Remplacer par le bon appel et les bon param
    data, sw1, sw2 = connection.transmit(
        [0xB0, 0x00, 0x00, 0x00, 0x02, int(pin[:2]), int(pin[2:]) ])
    #print(hex(sw1),hex(sw2))
    
    #print(sw1, sw2)
    data, sw1, sw2 = connection.transmit(
        [0xB0, 0x04, 0x00, 0x00, 0x00 ])
    vk = VerifyingKey.from_pem(open("client/publiccarte.pem").read())
    prenom =''
    info =''
    signature = ''
    if data != []:
        cpt = 0
        for i in data:
            if cpt<29:
                if cpt>24:
                    numparticipant += chr(i)
                d = hex(i)
                if(len(d)<4):
                    d = '0'+d
                info += d
            else :
                d = hex(i)
                if(len(d)<4):
                    d = '0'+d
                signature += d
            cpt +=1
        #print (numparticipant)
        info = info.replace('0x','')
        signature = signature.replace('0x','')
       # numparticipant=
        info=info.encode()
        signature=bytes.fromhex(signature)
        #=''.join(data[24:29])
        #Recup num participant
        try:
            vk.verify(signature, info)
            #print ("good signature")
            print("PIN vérifié, authentification réussie\n")
            return True
        except BadSignatureError:
            print ("BAD SIGNATURE")
            print("Carte non délivrée par nos équipes\n")
            sys.exit()
            return False
    
   


# Main
while True:
    montant = input("Bonjour veuillez rentrer le crédit à prelever\n")
    if montant > "0" and montant <= "500":
        r = readers()
        if r == []:
            if affiche == 0:
                print("Bonjour veuillez insérer une carte afin de l'initialiser\n")
                affiche += 1
        else:
            while r != []:
                print("Carte détécter\n")
                affiche = 0
                connection = connexion(r)
                pin = input(
                    "Bonjour veuillez rentrer votre code PIN pour procéder a un prélévement d'un montant de "+montant+" crédits\n")
                if len(pin) > 0 and len(pin) >= 4:
                    check = checkpin(pin, connection)
                    if check == True:
                        decrement_credit(montant)
                        deconnexion(connection)
                        print("Payement effectué, veuillez retirer la carte\n")
                    else:
                        print("Veuillez resaisir votre code PIN\n")
                else:
                    print("Format 4 chiffres du PIN non respécté\n")
                print("Deconnexion de la carte\n")
                deconnexion(connection)
                sys.exit()
    else:
        print("Le montant demandé doit être compris entre 1 et 500 crédits\n")
