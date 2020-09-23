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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.jsonrpc.transaction.*;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

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
    public void whatthehellamidoing() throws NoSuchAlgorithmException {
        String message = "hello world";
        byte[] byteMessage = message.getBytes(StandardCharsets.UTF_8);
        String receiversPubKey = "0465ca5e4ac66d894363e659af4bd79c99cae777f023d117e3af3b8609ba37948fb0abd858c068de4" +
                "1a67b016f22b2a013133bf7ba5a15fb3641e8248b0245364f";
        String privateKey = "024c3c5d58f1a178235761190339663cb51787684af9b2dd659047d7da276a05";


        byte[] derived = deriveECDHKeyAgreement(privateKey, receiversPubKey);

        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPrivateKeyParameters privKeyP =
                new ECPrivateKeyParameters(new BigInteger(derived, 16), domain);

        ECPoint q = domain.getCurve().decodePoint(Utils.toBytes(receiversPubKey));
        ECPublicKeyParameters pubKeyP = new ECPublicKeyParameters(q, domain);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));

        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(privKeyP);
        BigInteger ecdhKey = agreement.calculateAgreement(pubKeyP);

//        byte[] hashed = getSha2bit512Atype(ecdhKey);
        byte[] hashed = getSha2bit512Btype(ecdhKey.toByteArray());

        String hexEcdh = Utils.toHexStringNo0x(hashed);
        System.out.println("hexString ECDH : " + hexEcdh);

        byte[] ecdhPriKey = new byte[hashed.length / 2];
        byte[] keyForMac = new byte[hashed.length / 2];
        System.arraycopy(hashed, 0, ecdhPriKey, 0, ecdhPriKey.length);
        System.arraycopy(hashed, ecdhPriKey.length, keyForMac, 0, keyForMac.length);

        System.out.println("edchPriKey : " + Utils.toHexStringNo0x(ecdhPriKey));
        System.out.println("mac key : " + Utils.toHexStringNo0x(keyForMac));

        byte[] cipherText = getCiphertextAES256CBC(ecdhPriKey, byteMessage);
        System.out.println("ciphertext : " + Utils.toHexStringNo0x(cipherText));






        byte[] mac = new byte[16 + cipherText.length];
        System.arraycopy(Utils.toBytes("04" + Wallet.getPublicKey(privateKey)), 16, mac, 0, 16);
        System.arraycopy(cipherText, 0, mac, 16, cipherText.length);

        System.out.println("mac : " + Utils.toHexStringNo0x(mac));
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

    public static byte[] getCiphertextAES256CBC(byte[] ecdhPriKey, byte[] target) {
        try {

//            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
//
//            SecretKey tmp = factory.generateSecret(spec);
//            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            SecretKeySpec secretKeySpec =
                    new SecretKeySpec(Arrays.copyOfRange(ecdhPriKey, 0, 16), "AES");

            byte[] iv = Utils.toBytes(generateRandomHexStringNo0x(32));
            String sampleIv = "24210c037fb76e413fe8f938f46607c8";
            IvParameterSpec ivSpec = new IvParameterSpec(Utils.toBytes(sampleIv));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            return cipher.doFinal(target);
        }
        catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static byte[] deriveECDHKeyAgreement(String srcPrivKey, String destPubKey) {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

        ECPoint pudDestPoint = domain.getCurve().decodePoint(Utils.toBytes(destPubKey));
        ECPoint mult = pudDestPoint.multiply(new BigInteger(srcPrivKey, 16));
        return mult.getEncoded(true);
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
