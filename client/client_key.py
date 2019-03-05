from ecdsa import SigningKey, NIST256p



skcarte = SigningKey.generate(curve=NIST256p) #generation clef privée
vkcarte = skcarte.get_verifying_key() #génération clef publique
open("privatecarte.pem","w").write(skcarte.to_pem().decode())
open("publiccarte.pem","w").write(vkcarte.to_pem().decode())
    