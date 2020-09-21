package web3jv.crypto;

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

    @BeforeEach
    public void setUp() {
        web3jv = new StubWeb3jv();
        web3jv.setChainId(ChainId.ROPSTEN);
        encoder = new RlpEncoder();
        samplePriKey = "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e";
    }

    @DisplayName("송신자의 주소가 복호화된 주소와 같으면 참을 반환한다")
    @Test
    public void verifyReceivedTransactionTest1() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = RlpDecoder.decoder(receivedTx);

        assertTrue(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                Wallet.getAddressFromPrivateKey(samplePriKey),
                ChainId.ROPSTEN.toHexStringNo0x()
        ));
    }

    @DisplayName("송신 트랜젝션에 기록된 체인아이디와 검증메소드에 입력한 체인아이디가 다르면 거짓을 반환한다")
    @Test
    public void verifyReceivedTransactionTest2() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = RlpDecoder.decoder(receivedTx);

        assertFalse(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                Wallet.getAddressFromPrivateKey(samplePriKey),
                ChainId.MAIN.toHexStringNo0x()
        ));
    }

    @DisplayName("송신자의 주소와 다른 주소값을 검증메소드에 입력하면 거짓을 반환한다")
    @Test
    public void verifyReceivedTransactionTest3() {
        String receivedTx = getSampleSignedTxNo1();
        Transaction receivedDecoded = RlpDecoder.decoder(receivedTx);

        assertFalse(CryptoUtils.validateSignedTx(
                receivedDecoded,
                encoder,
                "0xa11CB28A6066684DB968075101031d3151dC40ED",
                ChainId.MAIN.toHexStringNo0x()
        ));
    }

    private String getSampleSignedTxNo1() {
        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("1"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(new BigInteger("21000"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .v(ChainId.ROPSTEN.toHexStringNo0x())
                .build();
        return transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
    }
}
