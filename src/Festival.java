//package festival;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public class Festival extends java.applet.Applet{

    public static final byte CLA_MONAPPLET = (byte) 0xB0;

    //déclaration des constantes du pin

    static final byte INS_CHECK_PIN = 0x00;
	static final byte INS_PRINT_SECRET = 0x01;
	static final byte INS_UPDATE_PIN = 0x02;
    static final byte INS_DEBUG = 0x03;

    private byte[] MESS_DEBUG = { 'D', 'e', 'B', 'U', 'G', ' ' };

	private static final byte PIN_LENGTH = 0x02;
	private static final byte PIN_TRY_LIMIT = 0x03;
	private static final byte SECRET_LENGTH = 0x02;

	static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	static final short SW_PIN_VERIFICATION_FAILED = 0x6302;

	private static byte[] secret;
	private static OwnerPIN m_pin;


}