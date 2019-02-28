from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from smartcard.System import readers
from logging.handlers import RotatingFileHandler
import os
import logging
import secrets
import ecdsa


def hex_to_str(value_hex):
    string_value=bytearray.fromhex(value_hex).decode()
    return string_value

def list_int_to_hex(list_in):
    stringhex=""
    for i in list_in:
        stringhex+=hex(i)
    stringstring=hex_to_str(stringhex[2:])
    return stringstring

val=hex(1885435244)

#print(val[2:])
#print(bytearray.fromhex([2:val]).decode())
list_in=[1885435244]  
print(list_int_to_hex(list_in))

#Paul en hexa 7061756c
#Paul dec 1885435244

#Ici, on veut tout d'abord faire une install en lancant lacommande d'install de cles en clip avec paramete --param PIN(2octets)Secret(2Octet)
#Questio: doit on générer des cles (2 octets pas beaucoup) ou secret définit par la personne en caissequi délivre les cartes
def init_carte(name,surname,pin):
    namehex=hex(name)+ ""
    surnamehex=hex(surname)+""
    pinhex=hex(pin) 
    clesecrete = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)#Géneration clé secrete 
    clepublic = clesecrete.get_verifying_key()#Génération clé publique 
    signdata = clesecrete.sign(b"message")#Exemple signature message
    clesecrete.verify(signdata, b"message") # True 


    namehex=hex(name)+ ""
    surnamehex=hex(surname)+""
    pinhex=hex(pin) 
    #ICi ce client devra choisir de locker la carte a la fin 
    cmd="gp -install blabka.cap --param" +pinhex+generatesecrets

# import ecdsa

# message = b"message"
# public_key = '98cedbb266d9fc38e41a169362708e0509e06b3040a5dfff6e08196f8d9e49cebfb4f4cb12aa7ac34b19f3b29a17f4e5464873f151fd699c2524e0b7843eb383'
# sig = '740894121e1c7f33b174153a7349f6899d0a1d2730e9cc59f674921d8aef73532f63edb9c5dba4877074a937448a37c5c485e0d53419297967e95e9b1bef630d'

# vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
# vk.verify(bytes.fromhex(sig), message) # True
#def send_data(applet,command,offset_data,data_length,data):
#   data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
        #Valeurs à définir
def decrement_credit(value):
    print("Demande de payement d'une valeur de "+value +"en cours...")
    hexvalue=hex(value)
    #Remplacer par le bon appel et les bon param
    #data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
    if (sw1=="0x90" and sw2=="0x00"):
        cred=list_int_to_hex(data)
        print("Payement de "+value +"crédits effectué il vous reste" +cred+ "crédits")
        logger.info("Payement effectué il vous reste" +cred+ "crédits")

    else:
        print("Echec du paiement")
        logger.warning("Echec du paiement")
def connexion():
    r=readers()
    connection=r[0].createConnection()
    connection.connect()
#Partie LOG
    # création de l'objet logger qui va nous servir à écrire dans les logs
    logger = logging.getLogger()
    # on met le niveau du logger à DEBUG, comme ça il écrit tout
    logger.setLevel(logging.DEBUG)
    #logger.setLevel(logging.RELEASE)
    
    # création d'un formateur qui va ajouter le temps, le niveau
    # de chaque message quand on écrira un message dans le log
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    # création d'un handler qui va rediriger une écriture du log vers
    # un fichier en mode 'append', avec 1 backup et une taille max de 1Mo
    file_handler = RotatingFileHandler('activity.log', 'a', 1000000, 1)
    # on lui met le niveau sur DEBUG, on lui dit qu'il doit utiliser le formateur
    # créé précédement et on ajoute ce handler au logger
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # création d'un second handler qui va rediriger chaque écriture de log
    # sur la console
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    logger.addHandler(stream_handler)


def deconnexion():
    connection.disconnect()


def checkpin(pin):
    pinvalue=hex(pin)
    #Remplacer par le bon appel et les bon param
    #data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08])
    if (sw1=="0x90" and sw2=="0x00"):
        return=list_int_to_hex(data)
        print("Connexion établie")
        return True
    else:
        print("Echec de vérification de pin")
        return False
def lock_cart(key):
    cmd = "gp -lock"+ key
    returned_value = os.system(cmd)  # returns the exit code in unix
    print('returned value:', returned_value)

def unlock_card(key):
    cmd="gp -key" +key+ "-unlock"
    returned_value = os.system(cmd)  # returns the exit code in unix
    print('returned value:', returned_value)    

#Main
#connexion()
while(true):
    input=input("Bonjour, veuillez rentrer votre PIN")
    if input==True:
        print("Quelle opération....")
    else:
        print("Echec du PIN ")



# hex to str(value_hex)
# list_int_to_hex(list)
# send_data(applet,command,offset_data,data_length,data)
# init_carte() -->  constructeur : init du secret, des crédits et du pin
# decrement_credit(value)
# log_transaction() --> log coté client uniquement
# lock_card(key)
# unlock_card(key)
# check_pin(pin)
# connexion()
# deconnexion()
# choose_applet()
