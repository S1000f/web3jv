package web3jv.crypto;

import net.consensys.cava.bytes.Bytes;
import net.consensys.cava.bytes.Bytes32;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ECDHKEKGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;
import web3jv.wallet.WalletFile;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

public class EncryptUtils {

    private static final int n_262144 = 262144;
    private static final int n_4096 = 4096;
    private static final int P = 1;

    private static final int R = 8;
    private static final int DERIVED_KEY_LENGTH = 32;

    private static final int CURRENT_VERSION = 3;

    private static final String CIPHER = "aes-128-ctr";
    private static final String AES_128_CTR = "pbkdf2";
    private static final String SCRYPT = "scrypt";

    public static String getKeccack256HexString(String publicKey) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        byte[] bytes = ByteUtils.fromHexString(publicKey); // keccak = 제로패딩 없어야 함

        return Hex.toHexString(keccak.digest(bytes));
    }

    public static String getKeccack256HexString(byte[] input) {
        return Hex.toHexString(getKeccack256Bytes(input));
    }

    public static byte[] getKeccack256Bytes(byte[] input) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        return keccak.digest(input);
    }

    public static BigInteger[] signMessageByECDSA(byte[] targetMessage, String hexPassword) {
        String message = "hello world";
        String receiversPubKey = "0465ca5e4ac66d894363e659af4bd79c99cae777f023d117e3af3b8609ba37948fb0abd858c068de4" +
                "1a67b016f22b2a013133bf7ba5a15fb3641e8248b0245364f";
        String receivesPrivateKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";
        //

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        //


        Digest digest = new SHA256Digest();
        ECDHKEKGenerator ecdhkekGenerator = new ECDHKEKGenerator(digest);


        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(params.getG(), domain);
        CipherParameters cipherParameters = new ECDHUPublicParameters(publicKeyParameters, publicKeyParameters);


        ECPrivateKeyParameters priKey =
                new ECPrivateKeyParameters(new BigInteger(receiversPubKey, 16), domain);
        CipherParameters cipherParameters2 = new ECDHUPrivateParameters(priKey, priKey);


        ECDHBasicAgreement ecdhBasicAgreement = new ECDHBasicAgreement();
        ecdhBasicAgreement.init(cipherParameters);

        BigInteger sigd = ecdhBasicAgreement.calculateAgreement(cipherParameters2);





        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priKey);

        byte[] messageHash = getKeccack256Bytes(targetMessage);

        BigInteger[] sigs = signer.generateSignature(messageHash);
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        return new BigInteger[] {r, s};
    }

    public static boolean validateSignECDSA(byte[] messageHash, String address, BigInteger r, BigInteger s) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && Wallet.getAddressNo0x(Utils.toHexStringNo0x(k.toByteArray()))
                    .equals(Utils.generifyAddress(address))) {
                return true;
            }
        }

        return false;
    }

    public static int findV(byte[] messageHash, String privateKey, BigInteger r, BigInteger s) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && k.equals(new BigInteger(Wallet.getPublicKey(privateKey), 16))) {
                recId = i;
                break;
            }
        }

        return recId;
    }

    private static BigInteger recoverFromSignedMessage(
            ECNamedCurveParameterSpec params,
            byte[] messageHash,
            BigInteger r,
            BigInteger s,
            int recId
    ) {
        BigInteger n = params.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(x, 1 + x9.getByteLength(params.getCurve()));
        compEnc[0] = (byte) (((recId & 1) == 1) ? 0x03 : 0x02);
        ECPoint R = params.getCurve().decodePoint(compEnc);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(params.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);

        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }








    public static BigInteger generateEcdhKey(String privKey, String theirPubKey) {
        String message = "hello world";
        String receiversPubKey = "0x0465ca5e4ac66d894363e659af4bd79c99cae777f023d117e3af3b8609ba37948fb0abd858c068de4" +
                "1a67b016f22b2a013133bf7ba5a15fb3641e8248b0245364f";
        String radomPrivateKey = "0x024c3c5d58f1a178235761190339663cb51787684af9b2dd659047d7da276a05";
        //

        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPrivateKeyParameters privKeyP =
                new ECPrivateKeyParameters(new BigInteger(privKey, 16), domain);

        ECPoint q = domain.getCurve().decodePoint(Utils.toBytes(theirPubKey));
        ECPublicKeyParameters pubKeyP = new ECPublicKeyParameters(q, domain);

        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privKeyP);

        return agreement.calculateAgreement(pubKeyP);
    }

    public static byte[] getSha2bit512Atype(BigInteger ecdh) {
        SHA512.Digest digest = new SHA512.Digest();
        return digest.digest(ecdh.toByteArray());
    }

    public static byte[] getSha2bit512Btype(byte[] ecdh) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512/256");
        digest.update(ecdh);

        return digest.digest(ecdh);
    }

    public static Bytes deriveECDHKeyAgreement(String srcPrivKey, String destPubKey) {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPoint pudDestPoint = domain.getCurve().decodePoint(Utils.toBytes(destPubKey));
        ECPoint mult = pudDestPoint.multiply(new BigInteger(srcPrivKey, 16));
        return Bytes.wrap(mult.getEncoded(true));
    }
























    public static void generateWalletFile(String password, String privateKey) {
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

    private static String generateRandomHexStringNo0x(int length) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < length; i++) {
            privateKey.append(Integer.toHexString(secureRandom.nextInt(16)));
        }

        return privateKey.toString();
    }

}
