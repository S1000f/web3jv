package web3jv.wallet;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import web3jv.crypto.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
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
    static final String AES_128_CTR = "pbkdf2";
    static final String SCRYPT = "scrypt";

    public String generatePrivateKey() {
        return generateRandomLength(64);
    }

    public String getPublicKey(String priKey) {
        byte[] priByte = (new BigInteger(priKey, 16)).toByteArray(); // ec = 제로패딩 있어야 함
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = params.getG().multiply(new BigInteger(priByte));

        return Hex.toHexString(pointQ.getEncoded(false)).substring(2);
    }

    public String getAddress(String pubKey) {
        String uncut = getKeccack256HexString(pubKey);
        return "0x" + uncut.substring(uncut.length() - 40);
    }

    public String getAddressFromPrivateKey(String privateKey) {
        return getAddress(getPublicKey(privateKey));
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

    public WalletFile generateWalletFile(String password, String privateKey) {

        /* Derived Key(파생 키)
        * 비밀번호를 솔트와 n, p, r 을 이용하여 Scrypt 방법으로 암호화 하여 파생키를 생성함
        * salt : 암호를 강화하기 위한 무작위의 난수집합
        * n :
        * r :
        * p :
        * DERIVED_KEY_LENGTH :
        * */
        byte[] salt = generateRandomBytes(32);
        int n = n_4096;
        int p = P;
        byte[] derivedKey = SCrypt.generate(password.getBytes(), salt, n, R, p, DERIVED_KEY_LENGTH);

        /* CipherText
        * 개인키를 iv 와 aes_ctr_encrypt 함수를 사용하여 암호화
        * */
        byte[] iv = generateRandomBytes(16);
        byte[] cipherText = new byte[0];
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec secretKeySpec =
                    new SecretKeySpec(Arrays.copyOfRange(derivedKey, 0, 16), "AES");
            cipher.init(1, secretKeySpec, ivParameterSpec);
            cipherText = cipher.doFinal(new BigInteger(privateKey, 16).toByteArray());
        } catch (Exception e) {
            e.getStackTrace();
        }

        /* mac(Message authentication code)
        * 암호화된 대상(메시지)이 유효한지 확인하고 복호화 할때 필요함
        * derivedkey 와 cipherText 를 사용하여 생성
        * */
        byte[] result = new byte[16 + cipherText.length];
        System.arraycopy(derivedKey, 16, result, 0, 16);
        System.arraycopy(cipherText, 0, result, 16, cipherText.length);
        byte[] mac = CryptoUtils.getKeccack256Bytes(result);

        return buildWalletFile(privateKey, salt, iv, cipherText, mac, n, p);
    }

    private WalletFile buildWalletFile(
            String privateKey,
            byte[] salt,
            byte[] iv,
            byte[] cipherText,
            byte[] mac,
            int n,
            int p
    ) {
        WalletFile walletFile = new WalletFile();
        walletFile.setAddress(getAddress(privateKey));
        walletFile.setId(UUID.randomUUID().toString());
        walletFile.setVersion(CURRENT_VERSION);

        WalletFile.Crypto crypto = new WalletFile.Crypto();
        crypto.setCipher(CIPHER);
        crypto.setCiphertext(Hex.toHexString(cipherText));
        crypto.setKdf(SCRYPT);
        crypto.setMac(Hex.toHexString(mac));

        WalletFile.Cipherparams cipherparams = new WalletFile.Cipherparams();
        cipherparams.setIv(Hex.toHexString(iv));

        WalletFile.Kdfparams kdfparams = new WalletFile.Kdfparams();
        kdfparams.setDklen(DERIVED_KEY_LENGTH);
        kdfparams.setN(n);
        kdfparams.setP(p);
        kdfparams.setR(R);
        kdfparams.setSalt(Hex.toHexString(salt));

        crypto.setCipherParams(cipherparams);
        crypto.setKdfparams(kdfparams);

        walletFile.setCrypto(crypto);

        return walletFile;
    }

    private byte[] generateRandomBytes(int length) {
        return generateRandomLength(length).getBytes();
    }

    private String generateRandomLength(int length) {
        Random random = new Random();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < length; i++) {
            privateKey.append(Integer.toHexString(random.nextInt(16)));
        }

        return privateKey.toString();
    }

}