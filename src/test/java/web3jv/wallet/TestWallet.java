package web3jv.wallet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestWallet {

    private Wallet wallet;

    @BeforeEach
    public void setUp() {
        wallet = new Wallet();
    }

    @DisplayName("개인키 입력시 공개키가 생성된다")
    @Test
    public void generatePublicKeyFromPrivateKey() {
        String SamplePriKey = "18dd1dcd752466afa3d1fac1424333c6461c3a0f1d6702e9c45bc9254ec74e5f";
        String result = wallet.getPublicKey(SamplePriKey);

        assertEquals("bdfb71e2d953406c45279ac434667a6a1ea9fae608af91e7f6bfb0792011df760895a528e8b8362288" +
                "6039b4803b6182d708fb40a16919bddaef84493ef1d4cf", result);
    }

    @DisplayName("개인키 입력시 주소가 생성된다")
    @Test
    public void generateAddress() {
        String privateKey = "66bf9bc7fe86b73a085d53555ce99add3a013ef0df86b209d4713361a77e6e89";
        String derived = "0xa11CB28A6066684DB968075101031d3151dC40ED";
        String expected = derived.toLowerCase();
        String address = wallet.getAddress(wallet.getPublicKey(privateKey));

        assertEquals(expected, address);
    }

    @DisplayName("주소입력시 EIP55 방식으로 인코딩된다")
    @Test
    public void encodeEIP55Test() {
        String result = Wallet.encodeEIP55("0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9");

        assertEquals("0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9", result);
    }

    @DisplayName("주소를 EIP55 체크섬으로 체크한다")
    @Test
    public void checkAddressEIP55Test() {
        String addressTest = "0xa11CB28A6066684DB968075101031d3151dC40ED";
        boolean result = Wallet.checkAddressEIP55(addressTest);

        assertTrue(Wallet.checkAddressEIP55("0x7b74C763119a062A52AEf110e949542f838bB660"));
        assertTrue(result);
    }
}
