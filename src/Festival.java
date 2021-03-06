package festival;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.*;
import javacard.security.*;


public class Festival extends Applet {

	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	// commandes

	static final byte INS_CHECK_PIN = 0x00;
	static final byte INS_GET_PUB = 0x01;
	static final byte INS_UPDATE_PIN = 0x02;
	static final byte INS_DEBUG = 0x03;
	static final byte INS_GET_INFO_CLIENT = 0x07;
	static final byte INS_DECREMENT = 0x08;
	static final byte INS_ECHANGE_CREDIT = 0x09;

	// debug
	private byte[] MESS_DEBUG = { 'D', 'e', 'B', 'U', 'G', ' ' };

	// tailles pour la chaine hex en paramètre d'install
	private static final byte PIN_LENGTH = 0x02;
	private static final byte PIN_TRY_LIMIT = 0x03;
	private static final byte FAM_NAME_LENGTH = 0x0c;
	private static final byte NAME_LENGTH = 0x0c;
	private static final byte NUM_PARTICIPANT_LENGTH = 0x05;
	private static final short SIGNATURE_LENGTH = 0x30;

	static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	static final short SW_PIN_VERIFICATION_FAILED = 0x6302;
	static final short SW_CREDIT_INSUFFISANT = 0x6363;

	// attributs (initialisés dans le constructeur)

	private static OwnerPIN m_pin;
	private static byte[] m_name;
	private static byte[] m_fam_name;
	private static byte[] m_num_participant;
	private static short m_credit;
	private static byte[] m_signature;
	private static PrivateKey m_secret_key;
	private static PublicKey m_public_key;

	private byte [] tempBuffer;
	private byte [] flags;
	private static final short FLAGS_SIZE = (short) 5;

	private short eccKeyLen;
	private Signature ecdsa;
	private KeyPair eccKey;

	// constructeur
	private Festival(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		byte aidLength = bArray[bOffset];
		short controlLength = (short) (bArray[(short) (bOffset + 1 + aidLength)] & (short) 0x00FF);
		short dataLength = (short) (bArray[(short) (bOffset + 1 + aidLength + 1 + controlLength)] & (short) 0x00FF);

		if ((byte) dataLength != (byte) (PIN_LENGTH + FAM_NAME_LENGTH + NAME_LENGTH + NUM_PARTICIPANT_LENGTH + SIGNATURE_LENGTH)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// récupération des data passés en paramètres 
		// exemple : gp -v --install Festival221.cap --params 0102426f
		// récupération pin
		m_pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_LENGTH);
		m_pin.update(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1), PIN_LENGTH);

		// récupération des infos du client et de la signature correspondante
		// nom de famille
		m_fam_name = new byte[(short) FAM_NAME_LENGTH];
		Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1 + PIN_LENGTH),
				m_fam_name, (short) 0, FAM_NAME_LENGTH);
		// prénom
		m_name = new byte[(short) NAME_LENGTH];
		Util.arrayCopyNonAtomic(bArray,
				(short) (bOffset + 1 + aidLength + 1 + controlLength + 1 + PIN_LENGTH + FAM_NAME_LENGTH), m_name,
				(short) 0, NAME_LENGTH);
		// numéro de participant
		m_num_participant = new byte[(short) NUM_PARTICIPANT_LENGTH];
		Util.arrayCopyNonAtomic(bArray,
				(short) (bOffset + 1 + aidLength + 1 + controlLength + 1 + PIN_LENGTH + FAM_NAME_LENGTH + NAME_LENGTH),
				m_num_participant, (short) 0, NUM_PARTICIPANT_LENGTH);
		// signature
		m_signature = new byte[(short) SIGNATURE_LENGTH];
		Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1 + PIN_LENGTH
				+ FAM_NAME_LENGTH + NAME_LENGTH + NUM_PARTICIPANT_LENGTH), m_signature, (short) 0, SIGNATURE_LENGTH);
		// création du couple clé privée/publique pour signer les transactions

			//création des variables de stockage temporaires
		tempBuffer = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_DESELECT);
		flags = JCSystem.makeTransientByteArray(FLAGS_SIZE, JCSystem.CLEAR_ON_RESET);

			//instance ECC(ALG_ECDSA_SHA)
		ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

		JCSystem.requestObjectDeletion();

		eccKey = new KeyPair(KeyPair.ALG_EC_FP,javacard.security.KeyBuilder.LENGTH_EC_FP_192);
		eccKeyLen = (short) 28;
		eccKey.genKeyPair();
		m_secret_key = eccKey.getPrivate();

		m_public_key = eccKey.getPublic();
	

	}
	
	// methode d'installation de l'applet sur la carte (appelée avec gp -v --install
	// Festival221.cap --params 0102426f)
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {

		// bArray,bOffset,bLength
		new Festival(bArray, bOffset, bLength).register();
	}
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (this.selectingApplet()) {
			return;
		}

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {

		// debug à virer après fin app
		case INS_DEBUG:

			m_pin.reset();

			Util.arrayCopyNonAtomic(MESS_DEBUG, (short) 0, buffer, (short) 0, (short) MESS_DEBUG.length);
			// Util.arrayCopyNonAtomic(secret, (short) 0, buffer, (short) MESS_DEBUG.length,
			// (short) secret.length);

			// buffer[(short) (MESS_DEBUG.length + secret.length)] =
			// m_pin.getTriesRemaining();

			apdu.setOutgoingAndSend((short) 0, (short) (MESS_DEBUG.length));// + secret.length + 1)); //secret = nb try
																			// restants pour pin

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

		case INS_GET_INFO_CLIENT:
			Util.arrayCopy(m_name, (short) 0, buffer, (short) 0, (short) m_name.length);
			Util.arrayCopy(m_fam_name, (short) 0, buffer, (short) m_name.length, (short) m_fam_name.length);
			Util.arrayCopy(m_num_participant, (short) 0, buffer, (short) (m_name.length + m_fam_name.length),
					(short) m_num_participant.length);
			apdu.setOutgoingAndSend((short) 0, (short) (m_name.length + m_fam_name.length + 1));
			break;

		case INS_DECREMENT: // ajouter signature à retourner au client python
			apdu.setIncomingAndReceive();
			byte temp = buffer[ISO7816.OFFSET_CDATA];
			if ((short)(m_credit - temp) <= (short)0) {
				// envoi msg erreur crédit insuffisant
				// Util.arrayCopy(SW_CREDIT_INSUFFISANT,(short)0,buffer,(short)0,(short)1);
				buffer[0] = (byte) (SW_CREDIT_INSUFFISANT & 0xFF);
				buffer[1] = (byte) ((SW_CREDIT_INSUFFISANT >> 8) & 0xFF);
				apdu.setOutgoingAndSend((short) 0, (short)2);

			} else {
				m_credit -= temp;
				// signature du nouveau montant sur la carte et du numéro de participant
				// récupération de la clé privée et création d'une signature
				byte[] str_to_sign = new byte[(short) (NUM_PARTICIPANT_LENGTH + 2 + SIGNATURE_LENGTH)];
				Util.arrayCopy(m_num_participant,(short)0,str_to_sign,(short)0,NUM_PARTICIPANT_LENGTH);
				str_to_sign[(short)(NUM_PARTICIPANT_LENGTH+1)] = (byte)(m_credit & 0xFF);
				str_to_sign[(short)(NUM_PARTICIPANT_LENGTH+2)] = (byte)((m_credit>>8) & 0xFF);
	
				ecdsa.init(m_secret_key,Signature.MODE_SIGN);
				ecdsa.sign(str_to_sign,(short) 0, (short)str_to_sign.length,buffer,(short)(NUM_PARTICIPANT_LENGTH + 3 ));
				apdu.setOutgoingAndSend((short) 0, (short)(NUM_PARTICIPANT_LENGTH + 2 + SIGNATURE_LENGTH));

				// envoi des infos signées au client TPE
				Util.arrayCopy(str_to_sign, (short) 0, buffer, (short) 0, (short) str_to_sign.length);
				apdu.setOutgoingAndSend((short) 0, (short) str_to_sign.length);
			}
			break;

			case INS_GET_PUB:

			ECPublicKey ECkey_to_send = (ECPublicKey)m_public_key;
			byte [] key_to_send= new byte[(short)56];
			ECkey_to_send.getW(key_to_send,(short)0);
			
			apdu.setOutgoingAndSend((short) 0,(short)64);
			break;

		case INS_ECHANGE_CREDIT:

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

}