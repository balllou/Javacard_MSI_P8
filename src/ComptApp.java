package compt;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
 
public class ComptApp extends Applet {
        public static final byte CLA_MONAPPLET = (byte) 0xB0;
        
        public static final byte INS_INCREMENTER_COMPTEUR = 0x00;
        public static final byte INS_DECREMENTER_COMPTEUR = 0x01;
        public static final byte INS_INTERROGER_COMPTEUR = 0x02;
        public static final byte INS_INITIALISER_COMPTEUR = 0x03;
        
        /* Attributs */
        private byte compteur;
        
        /* Constructeur */
        private ComptApp() {
               compteur = 0;
        }
 
        public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
               new ComptApp().register();
        }


public void process(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    
    if (this.selectingApplet()) return;
    
    if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_INCREMENTER_COMPTEUR:
                    compteur++;
                    break;

            case INS_DECREMENTER_COMPTEUR:
                    compteur--;
                    break;
                    
            case INS_INTERROGER_COMPTEUR:
                    buffer[0] = compteur;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    break;
                    
            case INS_INITIALISER_COMPTEUR:
                    apdu.setIncomingAndReceive();
                    compteur = buffer[ISO7816.OFFSET_CDATA];
                    break;
                    
            default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
}
