package web3jv.wallet;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import web3jv.crypto.CryptoUtils;
import web3jv.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import static web3jv.crypto.CryptoUtils.getKeccack256HexString;

public class Wallet {

    private static final int n_262144 = 262144;
    private static final int n_4096 = 4096;
    private static final int P = 1;

    private static final int R = 8;
    private static final int DERIVED_KEY_LENGTH = 32;

    private static final int CURRENT_VERSION = 3;

    private static final String CIPHER = "aes-128-ctr";
    private static final String AES_128_CTR = "pbkdf2";
    private static final String SCRYPT = "scrypt";

    public static String generatePrivateKey() {
        return generateRandomHexStringNo0x(64);
    }

    public static String getPublicKeyWith04(String priKey) {
        byte[] priByte = (new BigInteger(priKey, 16)).toByteArray(); // ec = 제로패딩 있어야 함
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = params.getG().multiply(new BigInteger(priByte));

        return Hex.toHexString(pointQ.getEncoded(false));
    }

    public static String getPublicKeyNo04(String privateKey) {
        return getPublicKeyWith04(privateKey).substring(2);
    }

    public static String getAddressNo0x(String pubKey) {
        String uncut = getKeccack256HexString(pubKey);
        return uncut.substring(uncut.length() - 40);
    }

    public static String getAddress0x(String pubKey) {
        return "0x" + getAddressNo0x(pubKey);
    }

    public static String getAddress0xFromPrivateKey(String privateKey) {
        return getAddress0x(getPublicKeyNo04(privateKey));
    }

    public static String getAddressNo0xFromPrivatKey(String privateKey) {
        return getAddressNo0x(getPublicKeyNo04(privateKey));
    }

    public static boolean checkAddressEIP55(String address) {
        String target = address.startsWith("0x") ? address.substring(2) : address;
        String lower = target.toLowerCase();
        char[] checksum = getKeccack256HexString(lower.getBytes()).toCharArray();
        char[] subject = target.toCharArray();
        for (int i = 0; i < target.length(); i++) {
            if (Character.isUpperCase(subject[i]) && checksum[i] < 56) {
                return false;
            }
        }

        return true;
    }

    public static String encodeEIP55(String address) {
        String target = address.startsWith("0x") ? address.substring(2) : address;
        String lower = target.toLowerCase();
        String addressHash = getKeccack256HexString(lower.getBytes());
        char[] subject = target.toCharArray();
        char[] checksum = addressHash.toCharArray();
        for (int i = 0; i < subject.length; i++) {
            if (checksum[i] >= 56) {
                subject[i] = Character.toUpperCase(subject[i]);
            }
        }

        return "0x" + String.valueOf(subject);
    }

    public static WalletFile generateWalletFile(String password, String privateKey) {
        /* Derived Key(파생 키)
        * 비밀번호를 솔트와 n, p, r 을 이용하여 Scrypt 방법으로 암호화 하여 파생키를 생성함
        * salt : 암호를 강화하기 위한 무작위의 난수집합
        * n :
        * r :
        * p :
        * DERIVED_KEY_LENGTH : 파생키의 길이 지정
        * */
        byte[] salt = Utils.toBytes(generateRandomHexStringNo0x(64));
        int n = n_4096;
        int r = R;
        int p = P;
        int dklen = DERIVED_KEY_LENGTH;
        byte[] derivedKey = generateDerivedKey(password, salt, n, r, p, dklen);

        /* CipherText
        * 개인키를 iv 와 aes_ctr_encrypt 함수를 사용하여 암호화
        * */
        byte[] iv = Utils.toBytes(generateRandomHexStringNo0x(32));
        byte[] cipherText = generateCipherText(1, iv, derivedKey, Utils.toBytes(privateKey));

        /* mac(Message authentication code)
        * 암호화된 대상(메시지)이 유효한지 확인하고 복호화 할때 필요함
        * derivedkey 와 cipherText 를 사용하여 생성
        * */
        byte[] mac = generateMac(derivedKey, cipherText);

        return buildWalletFile(privateKey, salt, iv, cipherText, mac, n, p);
    }

    public static String decryptWalletFile(String password, WalletFile walletFile) throws CipherSupportedException {
        WalletFile.Crypto crypto = walletFile.getCrypto();
        byte[] mac = Utils.toBytes(crypto.getMac());
        byte[] iv = Utils.toBytes(crypto.getCipherparams().getIv());
        byte[] cipherText = Utils.toBytes(crypto.getCiphertext());

        WalletFile.Kdfparams kdfParams = crypto.getKdfparams();
        byte[] derivedKey;
        int c;
        if (crypto.getKdf().toLowerCase().equals("scrypt")) {
            c = kdfParams.getDklen();
            int n = kdfParams.getN();
            int p = kdfParams.getP();
            int r = kdfParams.getR();
            byte[] salt = Utils.toBytes(kdfParams.getSalt());
            derivedKey = generateDerivedKey(password, salt, n, r, p, c);
        } else {
            throw new CipherSupportedException("Unable to decrypt params of :" + crypto.getKdf());
        }

        byte[] derivedMac = generateMac(derivedKey, cipherText);
        if (! Utils.toHexStringNo0x(mac).equals(Utils.toHexStringNo0x(derivedMac))) {
            throw new CipherSupportedException("Invalid password provided");
        } else {
            byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
            byte[] privateKey = generateCipherText(2, iv, encryptKey, cipherText);

            return Utils.toHexStringNo0x(privateKey);
        }
    }

    private static byte[] generateDerivedKey(String password, byte[] salt, int n, int r, int p, int dklen) {
        return SCrypt.generate(new BigInteger(password, 10).toByteArray(), salt, n, r, p, dklen);
    }

    private static byte[] generateCipherText(int mode, byte[] iv, byte[] derivedKey, byte[] target) {
        byte[] cipherText = new byte[0];
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec secretKeySpec =
                    new SecretKeySpec(Arrays.copyOfRange(derivedKey, 0, 16), "AES");
            cipher.init(mode, secretKeySpec, ivParameterSpec);
            cipherText = cipher.doFinal(target);
        } catch (Exception e) {
            e.getStackTrace();
        }

        return cipherText;
    }

    private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
        byte[] result = new byte[16 + cipherText.length];
        System.arraycopy(derivedKey, 16, result, 0, 16);
        System.arraycopy(cipherText, 0, result, 16, cipherText.length);

        return CryptoUtils.getKeccack256Bytes(result);
    }

    private static WalletFile buildWalletFile(
            String privateKey,
            byte[] salt,
            byte[] iv,
            byte[] cipherText,
            byte[] mac,
            int n,
            int p
    ) {
        WalletFile walletFile = new WalletFile();
        walletFile.setAddress(getAddressNo0xFromPrivatKey(privateKey));
        walletFile.setId(UUID.randomUUID().toString());
        walletFile.setVersion(CURRENT_VERSION);

        WalletFile.Crypto crypto = new WalletFile.Crypto();
        crypto.setCipher(CIPHER);
        crypto.setCiphertext(Hex.toHexString(cipherText));
        crypto.setKdf(SCRYPT);
        String hexStringMac = Hex.toHexString(mac);
        crypto.setMac(hexStringMac.startsWith("00") ? hexStringMac.substring(2) : hexStringMac);

        WalletFile.Cipherparams cipherparams = new WalletFile.Cipherparams();
        cipherparams.setIv(Hex.toHexString(iv));

        WalletFile.Kdfparams kdfparams = new WalletFile.Kdfparams();
        kdfparams.setDklen(DERIVED_KEY_LENGTH);
        kdfparams.setN(n);
        kdfparams.setP(p);
        kdfparams.setR(R);
        kdfparams.setSalt(Hex.toHexString(salt));

        crypto.setCipherparams(cipherparams);
        crypto.setKdfparams(kdfparams);

        walletFile.setCrypto(crypto);

        return walletFile;
    }

    public static String generateRandomHexStringNo0x(int length) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < length; i++) {
            privateKey.append(Integer.toHexString(secureRandom.nextInt(16)));
        }

        return privateKey.toString();
    }

}