package hellow;

import javacard.framework.Util;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
 
public class Hellow extends Applet {
        public static final byte CLA_MONAPPLET = (byte) 0xB0;
        
        public static final byte SAY_MY_NAME = 0x00;
        public static final byte SAY_HELLOW_MOTHERFUCKER = 0x01;
        public static final byte SAY_HELLOW_POLITE = 0x02;
        public static final byte I_GIVE_U_MY_NAME_U_BITCH = 0x03;
        
        /* Attributs */
        private byte [] name;
        
        /* Constructeur */
        private Hellow() {
               this.name = new byte[]{'h','a','h','a'};
        }
 
        public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
               new Hellow().register();
        }


public void process(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    
    if (this.selectingApplet()) return;
    
    if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    switch (buffer[ISO7816.OFFSET_INS]) {
            case SAY_MY_NAME:
                    Util.arrayCopy(name,(short)0,buffer,(short)0,(short)name.length);
                    apdu.setOutgoingAndSend((short) 0, (short) name.length);
                    break;

            case SAY_HELLOW_MOTHERFUCKER:
                    byte [] temp1={'h','e','l','l','o','w'};
                    byte [] temp2={'m','o','t','h','e','r','f','u','c','k','e','r'};
                    byte [] value={'h'};
                    Util.arrayCopy(temp1,(short)0,value,(short)0,(short)temp1.length);
                    Util.arrayCopy(name,(short)0,value,(short)temp1.length,(short)name.length);
                    Util.arrayCopy(temp2,(short)0,value,(short)(temp1.length+name.length),(short)temp2.length);
                    Util.arrayCopy(value,(short)0,buffer,(short)0,(short)value.length);
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    break;
                    
            case SAY_HELLOW_POLITE:
                    byte [] temp3={'h','e','l','l','o','w'};
                    Util.arrayCopy(temp3,(short)0,buffer,(short)0,(short)temp3.length);
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    break;
                    
            case I_GIVE_U_MY_NAME_U_BITCH:
                    apdu.setIncomingAndReceive();
                    Util.arrayCopy(buffer,ISO7816.OFFSET_CDATA,name,(short)0,(short)buffer.length);
                    break;
                    
            default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
}
