package festival;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

public class Festival extends java.applet.Applet {

	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	// déclaration des constantes du pin

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

	// déclaration des constantes du client

	static final byte INS_SET_NAME = 0x04;
	static final byte INS_SET_FAM_NAME = 0x05;
	static final byte INS_SET_NUM_PARTICIPANT = 0x06;
	static final byte INS_GET_INFO_CLIENT = 0x07;

	// instructions de traitement
	static final byte INS_DECREMENT = 0x08;
	static final byte INS_ECHANGE = 0x09;

	// déclaration des attributs de classe (initialisés dans le constructeur)
	private static byte[] secret;
	private static OwnerPIN m_pin;
	private static byte[] m_name;
	private static byte[] m_fam_name;
	private static byte m_num_participant;
	private static byte m_credit;

	// constructeur
	private Festival(byte[] bArray, short bOffset, byte bLength)
			throws ISOException {
		byte aidLength = bArray[bOffset];
		short controlLength = (short) (bArray[(short) (bOffset + 1 + aidLength)] & (short) 0x00FF);
		short dataLength = (short) (bArray[(short) (bOffset + 1 + aidLength + 1 + controlLength)] & (short) 0x00FF);

		if ((byte) dataLength != (byte) (PIN_LENGTH + SECRET_LENGTH)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// gp -v --install Festival221.cap --params 0102426f

		m_pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_LENGTH);
		m_pin.update(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1), PIN_LENGTH);

		secret = new byte[(short) SECRET_LENGTH];
		Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1 + PIN_LENGTH), secret,
				(short) 0, SECRET_LENGTH);

		m_name = new byte[] { 'j', 'e', 'a', 'n' };
		m_fam_name = new byte[] { 'b', 'o', 'n' };
		// m_fam_name=fam_name;
		// m_name=name;
		m_num_participant = 0;
		m_credit = (byte) 500;

	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {

		// bArray,bOffset,bLength
		new Festival(bArray, bOffset, bLength).register();
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (this.selectingApplet()){ return;}

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {

		// debug à virer après fin app
		case INS_DEBUG:

			m_pin.reset();

			Util.arrayCopyNonAtomic(MESS_DEBUG, (short) 0, buffer, (short) 0, (short) MESS_DEBUG.length);
			Util.arrayCopyNonAtomic(secret, (short) 0, buffer, (short) MESS_DEBUG.length, (short) secret.length);

			buffer[(short) (MESS_DEBUG.length + secret.length)] = m_pin.getTriesRemaining();

			apdu.setOutgoingAndSend((short) 0, (short) (MESS_DEBUG.length + secret.length + 1));

			break;

		case INS_CHECK_PIN:

			if (m_pin.isValidated()) {
				return;
			}

			if (verify(apdu)) {
				buffer[0] = m_pin.getTriesRemaining();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
				return;
			}

			ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
			break;

		case INS_PRINT_SECRET:

			print_secret(apdu);
			break;

		case INS_GET_INFO_CLIENT:
			Util.arrayCopy(m_name, (short) 0, buffer, (short) 0, (short) m_name.length);
			Util.arrayCopy(m_fam_name, (short) 0, buffer, (short) m_name.length, (short) m_fam_name.length);
			buffer[m_name.length + m_fam_name.length+1]=m_num_participant;
			apdu.setOutgoingAndSend((short) 0, (short) (m_name.length + m_fam_name.length + 1));
			break;
		case INS_SET_FAM_NAME:
			apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, m_fam_name, (short) 0, (short) buffer.length);
			break;

		case INS_SET_NAME:
			apdu.setIncomingAndReceive();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, m_name, (short) 0, (short) buffer.length);
			break;

		case INS_SET_NUM_PARTICIPANT:
			apdu.setIncomingAndReceive();
			m_num_participant= buffer[ISO7816.OFFSET_CDATA];
			break;
		case INS_DECREMENT:
			apdu.setIncomingAndReceive();
			m_credit -= buffer[ISO7816.OFFSET_CDATA];
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	static boolean verify(APDU apdu) throws ISOException {

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_LC] != PIN_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		apdu.setIncomingAndReceive();
		boolean res = m_pin.check(buffer, (short) ISO7816.OFFSET_CDATA, PIN_LENGTH);
		return res;
	}

	static void print_secret(APDU apdu) throws ISOException {

		byte[] buffer = apdu.getBuffer();

		if (m_pin.isValidated()) {

			Util.arrayCopyNonAtomic(secret, (short) 0, buffer, (short) 0, SECRET_LENGTH);
			// REMPLACER par une copie atomique
			apdu.setOutgoingAndSend((short) 0, (short) SECRET_LENGTH);
			return;
		}

		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

	}
}