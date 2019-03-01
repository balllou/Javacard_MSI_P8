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
affiche=0
logger = logging.getLogger()

def hex_to_str(value_hex):
    string_value=bytearray.fromhex(value_hex).decode()
    return string_value

def list_int_to_hex(list_in):
    stringhex=""
    for i in list_in:
        stringhex+=hex(i)
    stringstring=hex_to_str(stringhex[2:])
    return stringstring

def connexion(r):
    global logger
    connection=r[0].createConnection()
    connection.connect()
   # logger.info("Fournisseur de carte--- Connexion sur la carte")
    logger.setLevel(logging.DEBUG)
    #logger.setLevel(logging.RELEASE)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    file_handler = RotatingFileHandler('tpe.log', 'a', 1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)  
    print("Connexion de la carte\n")

def deconnexion():
    global logger 
    print("Déconnexion de la carte\n")
    connection.disconnect()


def decrement_credit(value):
    global logger
    print("Demande de payement d'une valeur de "+value +"en cours...\n")
    hexvalue=hex(value)
    #Remplacer par le bon appel et les bon param
    data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
    fichier = open("secretpublictpe", "r")
    publickey= fichier.readline()#numparti,montantactuel;signature
    for publickey in fichier:
        if data!=[]:
            messagesign=data[2].encode('ascii')
            numparticipant=data[0].encode('ascii')
            montantactuel=data[1].encode('ascii')
            message=numparticipant+montant
            verifkey = ecdsa.VerifyingKey.from_string(bytes.fromhex(publickey), curve=ecdsa.SECP256k1)
            result=verifkey.verify(bytes.fromhex(messagesign), message) # True
            if result==True:
                fichier.close()
                if (sw1=="0x90" and sw2=="0x00"):
                    print("Payement de "+value +"crédits effectué il vous reste" +montant+ "crédits\n")
                    logger.info("TPE--- Participant numéro"+numparticipant+"Payement effectué il vous reste" +montant+ "crédits")
                    return True
                else:
                    print("Echec du paiement\n")
                    fichier.close()
                    logger.info("TPE--- Participant numéro"+numparticipant+" Echec du paiement d'un montant de"+montant)
                    return False
        else:
            fichier.close()
            print("Aucune données reçu \n")
            return False
    fichier.close()
    print("Echec d'authentification de l'opération\n")
    return False

def checkpin(pin):
    global logger
    print("Vérification du code PIN en cours....\n")
    pinvalue=hex(pin)
    #Remplacer par le bon appel et les bon param
    data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
    fichier = open("secretpubliccarte", "r")
    for publickey in fichier:
    #Verification d'authentification
        if data!=[]:
            message=data[1].encode('ascii') 
            verifkey = ecdsa.VerifyingKey.from_string(bytes.fromhex(publickey), curve=ecdsa.SECP256k1)
            datasign=hex_to_str(data[2])
            result=verifkey.verify(bytes.fromhex(datasign), message) # True
            if result==True:
                fichier.close()
                #Si le retour carte est OK alors PIN OK
                if (sw1=="0x90" and sw2=="0x00"):
                    print("PIN vérifié, authentification réussie\n")
                    return True            
                else: 
                    print("Mauvais PIN echec d'authentification\n")
                    return False
        else:
            fichier.close()
            print("Aucune données reçu \n")
            return False
    fichier.close()
    print("Carte non délivrée par nos équipes\n")
    return False



#Main


while True:
    montant=input("Bonjour veuillez rentrer le crédit à prelever\n")
    if montant>"0" and montant<="500": 
        r=readers()
        if r==[]:
            if affiche==0:
                print("Bonjour veuillez insérer une carte afin de l'initialiser\n")
                affiche+=1
        else:
            while r!=[]:
                print("Carte détécter\n")
                affiche=0
                connexion()
                pin=input("Bonjour veuillez rentrer votre code PIN pour procéder a un prélévement d'un montant de"+montant+"crédits\n")
                if len(pin)>0 and len(pin)>=4:
                    check=checkpin(pin)
                    if check==True:
                        decrement_credit(montant)
                        deconnexion()
                        print("Payement effectué, veuillez retirer la carte\n")
                    else:
                        print("Veuillez resaisir votre code PIN\n")
                else: 
                    print("Format 4 chiffres du PIN non respécté\n")
                print("Deconnexion de la carte\n")
                deconnexion()
    print("Le montant demandé doit être compris entre 1 et 500 crédits\n")

