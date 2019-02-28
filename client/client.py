from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from smartcard.System import readers
from logging.handlers import RotatingFileHandler
import os
import logging




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
    #     # generate private/public key pair
    # key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, \
    #     key_size=2048)
    # # get public key in OpenSSH format
    # public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, \
    #     serialization.PublicFormat.OpenSSH)
    # # get private key in PEM container format
    # pem = key.private_bytes(encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.TraditionalOpenSSL,
    #     encryption_algorithm=serialization.NoEncryption())
    # # decode to printable strings
    # private_key_str = pem.decode('utf-8')
    # public_key_str = public_key.decode('utf-8')

    # print('Private key = ')
    # print(private_key_str)
    # print('Public key = ')
    # print(public_key_str)
    namehex=hex(name)+ ""
    surnamehex=hex(surname)+""
    pinhex=hex(pin) 
    #ICi ce client devra choisir de locker la carte a la fin 
    cmd="gp -install blabka.cap --param PIN+Key"


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
