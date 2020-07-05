import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoTools {
	private static final int ALPHABET_SIZE = 26;
	private static final int BITS_PER_BYTE = 8;
	private static final double[] LETTER_FREQUENCY_EN = {8.12, 1.49, 2.71, 4.32, 12.02, 2.3, 2.03, 5.92, 7.31, 0.1, 0.69, 3.98, 2.61, 6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.1, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07};

	/**
	 * Prevent instantiation
	 **/
	private CryptoTools() {}

	/**
	 * ASCII byte array: Convert lowercase characters to uppercase and strip non-letter characters
	 **/
	public static byte[] clean(byte[] arr) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		for (byte b : arr) {
			char c = (char) (b & 0xDF);
			if ('A' <= c && c <= 'Z') {
				bos.write(c);
			}
		}
		return bos.toByteArray();
	}

	/**
	 * Hex string -> Byte array
	 **/
	public static byte[] hexToBytes(String s) {
		if (s.length() % 2 != 0) {
			s += "0";
		}
		byte[] ret = new byte[s.length() / 2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = Byte.parseByte(s.substring(2 * i, 2 * i + 2), 16);
		}
		return ret;
	}

	/**
	 * Byte array -> Hex string
	 */
	public static String bytesToHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			int tmp = b & 0xFF;
			if (tmp < 16) {
				sb.append("0");
			}
			sb.append(Integer.toHexString(tmp));
		}
		return sb.toString().toUpperCase();
	}

	/**
	 * Byte array -> Bit string
	 */
	public static String bytesToBin(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			String tmp = Integer.toBinaryString(b & 0xFF);
			sb.append("0".repeat(BITS_PER_BYTE - tmp.length()));
			sb.append(tmp);
		}
		return sb.toString();
	}

	/**
	 * File -> Byte array
	 */
	public static byte[] fileToBytes(String filename) throws Exception {
		FileInputStream fis = new FileInputStream(filename);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte b;
		while ((b = (byte) fis.read()) != -1) {
			bos.write(b);
		}
		fis.close();
		return bos.toByteArray();
	}

	/**
	 * Byte array -> File
	 */
	public static void bytesToFile(byte[] data, String filename) throws Exception {
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(data);
		fos.close();
	}

	/**
	 * Byte array -> Hash digest
	 * Supported algorithms: MD2, MD5, SHA-1, SHA-256, SHA-384, and SHA-512
	 */
	public static byte[] hash(byte[] arr, String algo) throws Exception {
		return MessageDigest.getInstance(algo).digest(arr);
	}

	/**
	 * Cleaned byte array -> Letter frequency
	 **/
	public static int[] getFrequency(byte[] arr) {
		int[] freq = new int[ALPHABET_SIZE];
		for (byte b : arr) {
			freq[b - 'A']++;
		}
		return freq;
	}

	/**
	 * Cleaned byte array -> Index of coincidence, normalized to alphabet size
	 **/
	public static double getIC(byte[] arr, int interval) {
		double ret = 0;
		for (int offset = 0; offset < interval; offset++) {
			int n = 0;
			int[] freq = new int[ALPHABET_SIZE];
			for (int i = offset; i < arr.length; i += interval) {
				n++;
				freq[arr[i] - 'A']++;
			}
			int sum = 0;
			for (int f : freq) {
				sum += f * (f - 1);
			}
			ret += sum / (double) (n * (n - 1));
		}
		return ALPHABET_SIZE * ret / interval;
	}

	/**
	 * Hex string -> ASCII string
	 **/
	public static String hexToAscii(String s) {
		return bytesToAscii(hexToBytes(s));
	}

	/**
	 * ASCII string -> Hex string
	 **/
	public static String asciiToHex(String s) {
		return bytesToHex(asciiToBytes(s));
	}

	/**
	 * Byte array -> ASCII string
	 **/
	public static String bytesToAscii(byte[] b) {
		return new String(b);
	}

	/**
	 * ASCII string -> Byte array
	 **/
	public static byte[] asciiToBytes(String s) {
		return s.getBytes();
	}

	/**
	 * BigInteger -> Byte array
	 */
	public static byte[] bigIntegerToBytes(BigInteger b) {
		return b.toByteArray();
	}

	/**
	 * BigInteger -> ASCII string
	 */
	public static String bigIntegerToAscii(BigInteger b) {
		return bytesToAscii(bigIntegerToBytes(b));
	}

	public static byte[] crypt(boolean encrypt, String mode, byte[] text, byte[] key) throws Exception {
		Cipher c = Cipher.getInstance(mode);
		c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, mode.substring(0, 3)));
		return c.doFinal(text);
	}

	public static byte[] crypt(boolean encrypt, String mode, byte[] text, byte[] key, byte[] iv) throws Exception {
		Cipher c = Cipher.getInstance(mode);
		c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, mode.substring(0, 3)), new IvParameterSpec(iv));
		return c.doFinal(text);
	}

	/**
	 * Caesar cipher encryption/decryption
	 **/
	public static byte[] caesar(boolean encrypt, byte[] text, byte key) {
		for (int i = 0; i < text.length; i++) {
			text[i] = (byte) ((text[i] - 'A' + (encrypt ? key : ALPHABET_SIZE - key)) % ALPHABET_SIZE + 'A');
		}
		return text;
	}

	/**
	 * Finds the Caesar cipher key
	 **/
	public static byte caesarFindKey(byte[] text, int offset, int interval) {
		int[] freq = new int[ALPHABET_SIZE];
		for (int i = offset; i < text.length; i += interval) {
			freq[text[i] - 'A']++;
		}
		byte best = 0;
		double maxDP = 0;
		for (byte key = 0; key < ALPHABET_SIZE; key++) {
			double dotProd = 0;
			for (int i = 0; i < ALPHABET_SIZE; i++) {
				dotProd += freq[i] * LETTER_FREQUENCY_EN[(i - key + ALPHABET_SIZE) % ALPHABET_SIZE];
			}
			if (dotProd > maxDP) {
				maxDP = dotProd;
				best = key;
			}
		}
		return best;
	}

	/**
	 * Vigenère cipher encryption/decryption
	 **/
	public static byte[] vigenere(boolean encrypt, byte[] text, byte[] key) {
		for (int i = 0; i < text.length; i++) {
			text[i] = (byte) ((text[i] + (encrypt ? key[i % key.length] - 'A' - 'A' : ALPHABET_SIZE - key[i % key.length])) % ALPHABET_SIZE + 'A');
		}
		return text;
	}

	/**
	 * Finds the Vigenère cipher key of a given length
	 **/
	public static byte[] vigenereFindKey(byte[] text, int keyLen) {
		byte[] key = new byte[keyLen];
		for (int offset = 0; offset < keyLen; offset++) {
			key[offset] = caesarFindKey(text, offset, keyLen);
		}
		return key;
	}

	/**
	 * Transposition cipher encryption/decryption
	 **/
	public static byte[] transpose(boolean encrypt, byte[] text, byte key) {
		byte[] ret = new byte[text.length];
		for (int i = 0; i < text.length; i++) {
			ret[(encrypt ? i + key : i - key + text.length) % text.length] = text[i];
		}
		return ret;
	}
}
