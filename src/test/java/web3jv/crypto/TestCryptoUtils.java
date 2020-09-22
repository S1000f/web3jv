package web3jv.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.jsonrpc.transaction.*;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    public void test() {
        final String ETHEREUM_SPEC = "\u0019Ethereum Signed Message:\n";
        String message = "hello world";
        String privateKey = "97e416370613ca532c97bd84e4cc1d9aeb5d1e8e22cd6b660df3fa5823acfc71";

        byte[] messageBytes = Utils.toBytes(message);
        byte[] prefix = ETHEREUM_SPEC.concat(String.valueOf(messageBytes.length)).getBytes();

        byte[] result = new byte[prefix.length + messageBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(messageBytes, 0, result, prefix.length, messageBytes.length);




        String applied = ETHEREUM_SPEC + message.length() + message;
        byte[] messageHash = CryptoUtils.getKeccack256Bytes(Utils.toBytes(applied));

        BigInteger[] sigs = CryptoUtils.signMessageByECDSA(Utils.toBytes(applied), privateKey);
        BigInteger r = sigs[0], s = sigs[1];

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = CryptoUtils.recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && k.equals(new BigInteger(Wallet.getPublicKey(privateKey), 16))) {
                recId = i;
                break;
            }
        }

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        String v = Integer.toHexString(recId + 27);
        byte[] rBytes = r.toByteArray();
        String stringR = rBytes.length == 32 ? Hex.toHexString(rBytes) : Hex.toHexString(rBytes).substring(2);
        String stringS = Hex.toHexString(s.toByteArray());

        String signature = stringR + stringS + v;
        String answer = "0xcc1b5ae5b05e159d401271afe5d786babfe5456b32bf17d74479dfa9094564c457b3935bea2a88f0cfa387b8a2e923a6bafdefd44200f2461093481b71d6bdb81c";


        System.out.println("0x" + stringR);
        System.out.println("0xcc1b5ae5b05e159d401271afe5d786babfe5456b32bf17d74479dfa9094564c4");


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
