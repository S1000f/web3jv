package web3jv.wallet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestWallet {

    @Test
    public void generatePrivKeyAndAddress() throws Exception {

        String privateKey = "fdd8b595a0ba6ba01c04ab62bd1ab0fb6464fe44a3f32ac07ef236298e97e1aa";
        String address = Wallet.getAddress(privateKey);

        assertEquals("0x9Fab8C7A16B7cBAA1cF2B8568e8D1b3A59AEb827", address);
    }
}
