package web3jv.crypto;

import net.consensys.cava.bytes.Bytes;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.jsonrpc.transaction.*;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;
import web3jv.wallet.CipherSupportedException;
import web3jv.wallet.Wallet;
import web3jv.wallet.WalletFile;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class TestCryptoUtils {

    private Web3jvProvider web3jv;
    private String samplePriKey;
    private EncoderProvider encoder;
    private DecoderProvider decoder;
    private String wrongAddressSender;

    @BeforeEach
    public void setUp() {
        web3jv = new StubWeb3jv();
        web3jv.setChainId(ChainId.ROPSTEN);
        encoder = new RlpEncoder();
        decoder = new RlpDecoder();
        samplePriKey = "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e";
        wrongAddressSender = "0xa11CB28A6066684DB968075101031d3151dC40ED";
    }

    @DisplayName("송신자의 주소가 복호화된 주소와 같으면 참을 반환한다")
    @Test
    public void verifyReceivedTransactionTest1() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = decoder.decode(receivedTx);

        assertTrue(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                Wallet.getAddress0xFromPrivateKey(samplePriKey),
                ChainId.ROPSTEN.toHexStringNo0x()
        ));
    }

    @DisplayName("송신 트랜젝션에 기록된 체인아이디와 검증메소드에 입력한 체인아이디가 다르면 거짓을 반환한다")
    @Test
    public void verifyReceivedTransactionTest2() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = decoder.decode(receivedTx);

        assertFalse(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                Wallet.getAddress0xFromPrivateKey(samplePriKey),
                ChainId.MAIN.toHexStringNo0x()
        ));
    }

    @DisplayName("송신자의 주소와 다른 주소값을 검증메소드에 입력하면 거짓을 반환한다")
    @Test
    public void verifyReceivedTransactionTest3() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = decoder.decode(receivedTx);

        assertFalse(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                wrongAddressSender,
                ChainId.MAIN.toHexStringNo0x()
        ));
    }

    @DisplayName("오버로딩된 validateSignedTx 을 사용해도 올바른 결과가 나온다")
    @Test
    public void overloadedVerifyTransactionMethodTest() {
        String receivedTx = getSampleSignedTxNo1();

        assertTrue(CryptoUtils.validateSignedTx(
                receivedTx,
                decoder,
                encoder,
                Wallet.getAddress0xFromPrivateKey(samplePriKey),
                ChainId.ROPSTEN.toHexStringNo0x()
        ));
    }

    @DisplayName("이더리움 스펙 메시지 사이닝이 제대로 이뤄진다")
    @Test
    public void signMessageByEthereumPrefixThenGetSignature() {
        String message = "hello world";
        String privateKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";
        String answer = "0xcc1b5ae5b05e159d401271afe5d786babfe5456b32bf17d74479dfa9094564c457b3935bea2a88f0cfa387b8" +
                "a2e923a6bafdefd44200f2461093481b71d6bdb81c";

        String result = CryptoUtils.signMessageByEthPrefix(privateKey, message);

        assertEquals(answer, result);
    }

    @DisplayName("이더리움 스펙 시그니쳐를 검증한다")
    @Test
    public void verifyEthereumSpecMessageSignature() {
        String message = "hello world";
        String privateKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";
        String result = CryptoUtils.signMessageByEthPrefix(privateKey, message);

        assertTrue(CryptoUtils.validateEthSign(message, Wallet.getAddressNo0xFromPrivatKey(privateKey), result));
    }

    @Test
    public void whatthehellamidoing() throws Exception {

        String message = "hello world";
        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);
        String receiversPubKey = "0465ca5e4ac66d894363e659af4bd79c99cae777f023d117e3af3b8609ba37948fb0abd858c068de41a67b016f22b2a013133bf7ba5a15fb3641e8248b0245364f";
        String privateKey = "6a3f3fe8bf03f97d834bf30baa1142f384162f2636e4389c52e1ee3bfec75697";
        String myPublicKey = Wallet.getPublicKey(privateKey);
        String sampleIv = "42f5c934c04b1cc9b9225c084d002a68";

        byte[] ecdhkey = deriveECDHKeyAgreement(privateKey, receiversPubKey);

        byte[] cutEdch = Arrays.copyOfRange(ecdhkey, ecdhkey.length - 32, ecdhkey.length);

        byte[] hashed = getSha2bit512(cutEdch);

        byte[] ecdhPriKey = new byte[hashed.length / 2];
        byte[] keyForMac = new byte[hashed.length / 2];
        System.arraycopy(hashed, 0, ecdhPriKey, 0, ecdhPriKey.length);
        System.arraycopy(hashed, ecdhPriKey.length, keyForMac, 0, keyForMac.length);

        byte[] iv = Utils.toBytes(generateRandomHexStringNo0x(32));
        byte[] cipherText = getCiphertextAES256CBC(Cipher.ENCRYPT_MODE, iv, ecdhPriKey, byteMessage);

        byte[] sampleIvBytes = Utils.toBytes(sampleIv);
        byte[] ephemPubKey = Utils.toBytes(myPublicKey);

        int ivLength = sampleIvBytes.length;
        int ePubKeyLength = ephemPubKey.length;
        int cipherTextLength = cipherText.length;
        byte[] dataToMac = new byte[ivLength + ePubKeyLength + cipherTextLength];
        System.arraycopy(sampleIvBytes, 0, dataToMac, 0, ivLength);
        System.arraycopy(ephemPubKey, 0, dataToMac, ivLength, ePubKeyLength);
        System.arraycopy(cipherText, 0, dataToMac, ivLength + ePubKeyLength, cipherTextLength);

        byte[] mac = generateHmacSHA256(keyForMac, dataToMac);

        System.out.println(Utils.toHexStringNo0x(mac));

    }

    public static byte[] getSha2bit512(BigInteger ecdh) {
        SHA512.Digest digest = new SHA512.Digest();
        return digest.digest(ecdh.toByteArray());
    }

    public static byte[] getSha2bit512(byte[] ecdh) {
        SHA512.Digest digest = new SHA512.Digest();
        return digest.digest(ecdh);
    }

    public static byte[] getCiphertextAES256CBC(int mode, byte[] iv, byte[] ecdhPriKey, byte[] target) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(ecdhPriKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, secretKeySpec, ivSpec);

        return cipher.doFinal(target);

    }

    public static byte[] deriveECDHKeyAgreement(String srcPrivKey, String destPubKey) {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain =
                new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPoint pudDestPoint = domain.getCurve().decodePoint(Utils.toBytes(destPubKey));
        ECPoint mult = pudDestPoint.multiply(new BigInteger(srcPrivKey, 16));
        return mult.getEncoded(true);
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

    private static byte[] generateHmacSHA256(byte[] macKey, byte[] dataToMac) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(macKey, "AES");
        hmac.init(secretKeySpec);

        return hmac.doFinal(dataToMac);
    }

    @Test
    public void main() throws Exception {
        String message = "hello world";
        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);
        String BPrivKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";
        String APubKey = "041fd27f330f0a0d1caeb87ffd0bd29822c245206d5aefd2e87d8dad75cca79a7ea878c8c70ec83438370b4d4f4d472eb677620a3bd6fb45cc7d98d6dda37e1cca";
        String cipherText = "bda131d7b04b644dfb3a2ef5816e4618";
        byte[] cipherByte = Utils.toBytes(cipherText);
        String iv = "42f5c934c04b1cc9b9225c084d002a68";
        byte[] ivByte = Utils.toBytes(iv);
        String receivedMac = "90207c3723922edaf3c3c8b6433f8fc41c5cc7d253231e5ab949db4de98e5ba9";
        byte[] macBytes = Utils.toBytes(receivedMac);

        String decryptResult = decrypt1111(BPrivKey, APubKey, cipherByte, ivByte, macBytes);
        System.out.println(decryptResult);
        System.out.println(Utils.toHexStringNo0x(byteMessage));

    }

    public static String decrypt1111(String srcPrivKey, String destPubKey, byte[] cipherText, byte[] iv, byte[] givenMac) throws Exception {

        byte[] derivedECDHKey = deriveECDHKeyAgreement(srcPrivKey, destPubKey);
        byte[] cutEdch = Arrays.copyOfRange(derivedECDHKey, derivedECDHKey.length - 32, derivedECDHKey.length);

        byte[] hashed = getSha2bit512(cutEdch);

        byte[] ecdhPriKey = new byte[hashed.length / 2];
        byte[] keyForMac = new byte[hashed.length / 2];
        System.arraycopy(hashed, 0, ecdhPriKey, 0, ecdhPriKey.length);
        System.arraycopy(hashed, ecdhPriKey.length, keyForMac, 0, keyForMac.length);


        int ivLength = iv.length;
        String ephemPubKey = Wallet.getPublicKey(srcPrivKey);
        byte[] ePubKeyByte = Utils.toBytes(destPubKey);
        int ePubKeyLength = ePubKeyByte.length;
        int cipherTextLength = cipherText.length;
        System.out.println(ephemPubKey);

        byte[] dataToMac = new byte[ivLength + ePubKeyLength + cipherTextLength];
        System.arraycopy(iv, 0, dataToMac, 0, ivLength);
        System.arraycopy(ePubKeyByte, 0, dataToMac, ivLength, ePubKeyLength);
        System.arraycopy(cipherText, 0, dataToMac, ivLength + ePubKeyLength, cipherTextLength);
        System.out.println("dataToMac : " + Utils.toHexStringNo0x(dataToMac));

        byte[] derivedMac = generateHmacSHA256(keyForMac, dataToMac);

        System.out.println(Utils.toHexStringNo0x(givenMac));
        System.out.println(Utils.toHexStringNo0x(derivedMac));

        if (! Utils.toHexStringNo0x(givenMac).equals(Utils.toHexStringNo0x(derivedMac))) {
            throw new CipherSupportedException("Invalid password provided");
        } else {
            byte[] privateKey = getCiphertextAES256CBC(Cipher.DECRYPT_MODE, iv, ecdhPriKey, cipherText);
            return Utils.toHexStringNo0x(privateKey);
        }
    }

    private static byte[] generateDerivedKey(String password, byte[] salt, int n, int r, int p, int dklen) {
        return SCrypt.generate(new BigInteger(password, 10).toByteArray(), salt, n, r, p, dklen);
    }

    private static String generateRandomHexStringNo0x(int length) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < length; i++) {
            privateKey.append(Integer.toHexString(secureRandom.nextInt(16)));
        }

        return privateKey.toString();
    }

    private String getSampleSignedTxNo1() {
        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("1"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(new BigInteger("21000"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .chainId(ChainId.ROPSTEN.toHexStringNo0x())
                .build();
        return transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
    }
}
