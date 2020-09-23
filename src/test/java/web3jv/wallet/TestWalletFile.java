package web3jv.wallet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TestWalletFile {

    private String password;
    private String privateKey;
    private String address;

    @BeforeEach
    public void setUp() {
        password = "12121212";
        privateKey = "ff4a5c68bd14cc1bb762274a18b3777bd049456f73c8dd0a0df0cd80bec1812f";
        address = "4038aa65ab984c1816c0e27c54da14ac21e93643";

    }

    @DisplayName("ciphertext 가 정상적으로 생성된다")
    @Test
    public void createWalletFileTest() {
        WalletFile file = Wallet.generateWalletFile(password, privateKey);
        WalletFile.Crypto crypto = file.getCrypto();

        assertEquals("4038aa65ab984c1816c0e27c54da14ac21e93643", file.getAddress());
        assertFalse(crypto.getCiphertext().isEmpty());
    }

    @DisplayName("비밀번호와 키스토어 파일이 있다면 비밀키를 복호화 할 수 있다")
    @Test
    public void decryptWalletFileThenGetPrivateKey() throws CipherSupportedException {
        WalletFile file = Wallet.generateWalletFile(password, privateKey);
        String recoveredPriKey = Wallet.decryptWalletFile(password, file);

        assertEquals(privateKey, recoveredPriKey);
    }
}
