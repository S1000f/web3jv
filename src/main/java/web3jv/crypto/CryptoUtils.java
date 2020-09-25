package web3jv.crypto;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import web3jv.jsonrpc.transaction.DecoderProvider;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.Transaction;
import web3jv.utils.Utils;
import web3jv.wallet.CipherSupportedException;
import web3jv.wallet.Wallet;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CryptoUtils {

    private static final String ETHEREUM_SPEC = "\u0019Ethereum Signed Message:\n";

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

    public static byte[] getSha2bit512(byte[] ecdh) {
        SHA512.Digest digest = new SHA512.Digest();
        return digest.digest(ecdh);
    }

    public static byte[] getSha2bit512(BigInteger ecdh) {
        return getSha2bit512(ecdh.toByteArray());
    }

    public static BigInteger[] signMessageByECDSA(byte[] targetMessage, String hexPassword) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        ECPrivateKeyParameters priKey =
                new ECPrivateKeyParameters(new BigInteger(hexPassword, 16), domain);
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

    public static String signMessageByEthPrefix(String privateKey, String message) {
        byte[] result = buildEthPrefixMessage(message);
        byte[] messageHash = CryptoUtils.getKeccack256Bytes(result);

        BigInteger[] sigs = CryptoUtils.signMessageByECDSA(result, privateKey);
        BigInteger r = sigs[0], s = sigs[1];

        int recId = getEIP155v(messageHash, privateKey, r, s);
        String v = Integer.toHexString(recId + 27);
        byte[] rBytes = r.toByteArray();
        String stringR = rBytes.length == 32 ? Hex.toHexString(rBytes) : Hex.toHexString(rBytes).substring(2);
        String stringS = Hex.toHexString(s.toByteArray());

        return  "0x" + stringR + stringS + v;
    }

    public static boolean validateEthSign(String message, String address, String signature) {
        byte[] messageHash = CryptoUtils.getKeccack256Bytes(buildEthPrefixMessage(message));
        String removed = signature.startsWith("0x") ? signature.substring(2) : signature;
        String r = removed.substring(0, 64);
        String s = removed.substring(64, 64 + 64);

        return validateSignECDSA(messageHash, address, new BigInteger(r, 16), new BigInteger(s, 16));
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션의 객체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @param <T> extends {@link Transaction}
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static <T extends Transaction> boolean validateSignedTx(
            T receivedTx,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        encoder.setNonce(receivedTx.getNonce());
        encoder.setGasPrice(receivedTx.getGasPrice());
        encoder.setGasLimit(receivedTx.getGasLimit());
        encoder.setTo(receivedTx.getTo());
        encoder.setValue(receivedTx.getValue());
        encoder.setData(receivedTx.getData());
        encoder.setV(chainId);
        encoder.setR("");
        encoder.setS("");
        byte[] messageHash = getKeccack256Bytes(encoder.encode());

        BigInteger r = new BigInteger(receivedTx.getR(), 16);
        BigInteger s = new BigInteger(receivedTx.getS(), 16);

        return validateSignECDSA(messageHash, address, r, s);
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션
     * @param decoder 수신한 트랜젝션에 사용된 디코더 객체 혹은 그 디코딩 체계의 구현체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static boolean validateSignedTx(
            byte[] receivedTx,
            DecoderProvider decoder,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        return validateSignedTx(decoder.decode(receivedTx), encoder, address, chainId);
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션
     * @param decoder 수신한 트랜젝션에 사용된 디코더 객체 혹은 그 디코딩 체계의 구현체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static boolean validateSignedTx(
            String receivedTx,
            DecoderProvider decoder,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        return validateSignedTx(decoder.decode(receivedTx), encoder, address, chainId);
    }

    public static int getEIP155v(byte[] messageHash, String privateKey, BigInteger r, BigInteger s) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = CryptoUtils.recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && k.equals(new BigInteger(Wallet.getPublicKeyNo04(privateKey), 16))) {
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

    /**
     * <p>ECDH 와 AES-256-cbc 을 사용하여 공개키기반 암호화를 수행한다. 암호화
     * 하려는 평문과 상대방으로 부터 수신한 공개키를 필수 입력한다. 암호화에 사용될
     * 개인키와 정수팩터(iv)에 <i>null</i> 전달 시 자동으로 생성된 값을 사용한다</p>
     * @param message 암호화 하려는 평문
     * @param givenPublicKey 상대방으로부터 수신한 공개키
     * @param privateKey {@code @Nullable} <i>null</i> 전달시 개인키는 자동 생성됨
     * @param iv {@code @Nullable} <i>null</i> 전달시 iv는 자동 생성됨
     * @return ephemeral publicKey, cipherText, iv, mac 순서로 담긴 리스트
     * @throws Exception 암호화 실패시 발생
     * @see CryptoUtils#decryptECDH(String, String, byte[], byte[], byte[])
     * @since 0.1.0
     */
    public static List<byte[]> encryptByECDH(
            String message,
            String givenPublicKey,
            String privateKey,
            byte[] iv
    ) throws Exception {
        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);
        String cut0x = givenPublicKey.startsWith("0x") ? givenPublicKey.substring(2) : givenPublicKey;
        String receiversPubKey = cut0x.startsWith("04") ? cut0x : "04" + cut0x;
        String privKey = privateKey == null ? Wallet.generatePrivateKey() : privateKey;
        String myPublicKey = Wallet.getPublicKeyWith04(privKey);
        byte[] ephemPubKeyBytes = Utils.toBytes(myPublicKey);

        List<byte[]> ecdhResult = generateECDHagreement(privKey, receiversPubKey);
        byte[] ecdhPriKey = ecdhResult.get(0);
        byte[] keyForMac = ecdhResult.get(1);

        byte[] intVector = iv == null ? Utils.toBytes(Wallet.generateRandomHexStringNo0x(32)) : iv;
        byte[] cipherText = getCiphertextAES256CBC(Cipher.ENCRYPT_MODE, intVector, ecdhPriKey, byteMessage);

        byte[] dataToMac = buildDataToMac(intVector, ephemPubKeyBytes, cipherText);
        byte[] mac = generateHmacSHA256(keyForMac, dataToMac);

        return new ArrayList<>(Arrays.asList(ephemPubKeyBytes, cipherText, intVector, mac));
    }

    /**
     * <p>ECDH 와 AES-256-cbc 방식으로 암호화된 메시지를 복호화한다.</p>
     * @param srcPrivKey 상대방에게 전송한 공개키를 생성할 때 사용된 개인키
     * @param givenPublicKey 수신한 받은 공개키
     * @param cipherText 수신한 암호화된 메시지
     * @param iv 수신한 정수팩터
     * @param givenMac 수신한 메시지인증코드
     * @return 복호화된 값
     * @throws Exception 암호화 실패시 발생
     * @see CryptoUtils#encryptByECDH(String, String, String, byte[])
     * @since 0.1.0
     */
    public static byte[] decryptECDH(
            String srcPrivKey,
            String givenPublicKey,
            byte[] cipherText,
            byte[] iv,
            byte[] givenMac
    ) throws Exception {
        String theirAddress = (givenPublicKey.length() == 128 && ! givenPublicKey.startsWith("04")) ?
                "04" + givenPublicKey : givenPublicKey;

        List<byte[]> ecdhResult = generateECDHagreement(srcPrivKey, theirAddress);
        byte[] ecdhPriKey = ecdhResult.get(0);
        byte[] keyForMac = ecdhResult.get(1);

        byte[] ePubKeyByte = Utils.toBytes(theirAddress);
        byte[] dataToMac = buildDataToMac(iv, ePubKeyByte, cipherText);

        byte[] derivedMac = generateHmacSHA256(keyForMac, dataToMac);

        if (! Utils.toHexStringNo0x(givenMac).equals(Utils.toHexStringNo0x(derivedMac))) {
            throw new CipherSupportedException("Invalid password provided");
        } else {
            return getCiphertextAES256CBC(Cipher.DECRYPT_MODE, iv, ecdhPriKey, cipherText);
        }
    }

    public static byte[] deriveECDHKeyAgreement(String srcPrivKey, String destPubKey) {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain =
                new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPoint pudDestPoint = domain.getCurve().decodePoint(Utils.toBytes(destPubKey));
        ECPoint mult = pudDestPoint.multiply(new BigInteger(srcPrivKey, 16));

        return mult.getEncoded(true);
    }

    public static byte[] getCiphertextAES256CBC(int mode, byte[] iv, byte[] ecdhPriKey, byte[] target) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(ecdhPriKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, secretKeySpec, ivSpec);

        return cipher.doFinal(target);
    }

    public static byte[] generateHmacSHA256(byte[] password, byte[] target)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(password, "AES");
        hmac.init(secretKeySpec);

        return hmac.doFinal(target);
    }

    private static List<byte[]> generateECDHagreement(String privateKey, String publicKey) {
        byte[] derivedECDHKey = deriveECDHKeyAgreement(privateKey, publicKey);
        byte[] cutEdch = Arrays.copyOfRange(derivedECDHKey, derivedECDHKey.length - 32, derivedECDHKey.length);

        byte[] hashed = getSha2bit512(cutEdch);

        byte[] ecdhPriKey = new byte[hashed.length / 2];
        byte[] keyForMac = new byte[hashed.length / 2];
        System.arraycopy(hashed, 0, ecdhPriKey, 0, ecdhPriKey.length);
        System.arraycopy(hashed, ecdhPriKey.length, keyForMac, 0, keyForMac.length);

        List<byte[]> ecdh = new ArrayList<>(2);
        ecdh.add(ecdhPriKey);
        ecdh.add(keyForMac);

        return ecdh;
    }

    private static byte[] buildDataToMac(byte[] iv, byte[] publicKey, byte[] cipherText) {
        int ivLength = iv.length;
        int ePubKeyLength = publicKey.length;
        int cipherTextLength = cipherText.length;

        byte[] dataToMac = new byte[ivLength + ePubKeyLength + cipherTextLength];
        System.arraycopy(iv, 0, dataToMac, 0, ivLength);
        System.arraycopy(publicKey, 0, dataToMac, ivLength, ePubKeyLength);
        System.arraycopy(cipherText, 0, dataToMac, ivLength + ePubKeyLength, cipherTextLength);

        return dataToMac;
    }

    private static byte[] buildEthPrefixMessage(String message) {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] prefix = ETHEREUM_SPEC.concat(String.valueOf(messageBytes.length)).getBytes();

        byte[] result = new byte[prefix.length + messageBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(messageBytes, 0, result, prefix.length, messageBytes.length);

        return result;
    }
}

