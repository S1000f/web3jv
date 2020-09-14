package web3jv.wallet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestWallet {

    @Test
    public void generateAddress() {

        String privateKey = "fdd8b595a0ba6ba01c04ab62bd1ab0fb6464fe44a3f32ac07ef236298e97e1aa";
        String address = Wallet.getAddress(Wallet.getPublicKey(privateKey));

        assertEquals("0x9Fab8C7A16B7cBAA1cF2B8568e8D1b3A59AEb827", address);
    }

    @DisplayName("개인키 입력시 공개키 생성되는지 테스트")
    @Test
    public void generatePublicKeyFromPrivateKey() {

        String SamplePriKey = "18dd1dcd752466afa3d1fac1424333c6461c3a0f1d6702e9c45bc9254ec74e5f";
        String result = Wallet.getPublicKey(SamplePriKey);

        assertEquals("bdfb71e2d953406c45279ac434667a6a1ea9fae608af91e7f6bfb0792011df760895a528e8b8362288" +
                "6039b4803b6182d708fb40a16919bddaef84493ef1d4cf", result);
    }

    @Test
    public void addressChecksumEIP55Test() {

        String addressTest = "0x9Fab8C7A16B7cBAA1cF2B8568e8D1b3A59AEb827";
        boolean result = Wallet.checkAddressEIP55(addressTest);

        assertTrue(result);
    }
}
