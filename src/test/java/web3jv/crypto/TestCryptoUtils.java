package web3jv.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.DefaultChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.jsonrpc.transaction.*;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

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
        web3jv.setChainId(DefaultChainId.ROPSTEN);
        encoder = new RlpEncoder();
        decoder = new RlpEncoder();
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
                DefaultChainId.ROPSTEN.toHexStringNo0x()
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
                DefaultChainId.MAIN.toHexStringNo0x()
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
                DefaultChainId.MAIN.toHexStringNo0x()
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
                DefaultChainId.ROPSTEN.toHexStringNo0x()
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

    @DisplayName("ECDH 와 AES-256-CBC 을 사용하여 암호화하면 iv, ephemeral Public Key, cipher, mac 을 얻는다")
    @Test
    public void encryptMessageByECDHandAES256CBCthenGetCipherAndMac() throws Exception {
        String message = "hello world";
        String receiversPubKey = "0465ca5e4ac66d894363e659af4bd79c99cae777f023d117e3af3b8609ba37948fb0abd858c06" +
                "8de41a67b016f22b2a013133bf7ba5a15fb3641e8248b0245364f";
        String samplePrivKey = "6a3f3fe8bf03f97d834bf30baa1142f384162f2636e4389c52e1ee3bfec75697";
        String sampleIv = "42f5c934c04b1cc9b9225c084d002a68";
        byte[] sampleIvBytes = Utils.toBytes(sampleIv);

        List<byte[]> result = CryptoUtils.encryptByECDH(message, receiversPubKey, samplePrivKey, sampleIvBytes);
        String ephemPublic = Utils.toHexStringNo0x(result.get(0));
        String cipherText = Utils.toHexStringNo0x(result.get(1));
        String mac = Utils.toHexStringNo0x(result.get(3));

        assertEquals("041fd27f330f0a0d1caeb87ffd0bd29822c245206d5aefd2e87d8dad75cca79a7ea878c8c70ec834383" +
                "70b4d4f4d472eb677620a3bd6fb45cc7d98d6dda37e1cca", ephemPublic);
        assertEquals("bda131d7b04b644dfb3a2ef5816e4618", cipherText);
        assertEquals("90207c3723922edaf3c3c8b6433f8fc41c5cc7d253231e5ab949db4de98e5ba9", mac);
    }

    @DisplayName("ECDH 와 AES-256-cbc 로 암호화된 메시지를 복호화 가능하다")
    @Test
    public void canDecryptCipherWithGivenIvAndMacAndSourcePrivKey() throws Exception {
        String message = "hello world";
        String BPrivKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";
        String APubKey = "041fd27f330f0a0d1caeb87ffd0bd29822c245206d5aefd2e87d8dad75cca79a7ea878c8c70ec83438370b4d4f" +
                "4d472eb677620a3bd6fb45cc7d98d6dda37e1cca";
        String cipherText = "bda131d7b04b644dfb3a2ef5816e4618";
        byte[] cipherByte = Utils.toBytes(cipherText);
        String iv = "42f5c934c04b1cc9b9225c084d002a68";
        byte[] ivByte = Utils.toBytes(iv);
        String receivedMac = "90207c3723922edaf3c3c8b6433f8fc41c5cc7d253231e5ab949db4de98e5ba9";
        byte[] macBytes = Utils.toBytes(receivedMac);

        byte[] decrypted = CryptoUtils.decryptECDH(BPrivKey, APubKey, cipherByte, ivByte, macBytes);
        String decryptedString = new String(decrypted, StandardCharsets.UTF_8);

        assertEquals(message, decryptedString);
    }

    private String getSampleSignedTxNo1() {
        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("1"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(new BigInteger("21000"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .chainId(DefaultChainId.ROPSTEN)
                .build();
        return transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
    }
}
