package web3jv.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestWalletUtils {

    private final ObjectMapper mapper = new ObjectMapper();
    private String privateKey;
    private String password;
    private WalletFile walletFile;

    @BeforeEach
    public void setUp() throws InterruptedException {
        privateKey = "ff4a5c68bd14cc1bb762274a18b3777bd049456f73c8dd0a0df0cd80bec1812f";
        password = "12121212";
        walletFile = Wallet.generateWalletFile(password, privateKey);
    }

    @DisplayName("운영체제별로 올바른 경로가 설정되고 필요시 디렉토리를 생성한다")
    @Test
    public void canAccessAndCreateDirectoryForKeystore() throws IOException {
        boolean result = WalletUtils.saveKeystore(
                walletFile,
                Paths.get(WalletUtils.getDefaultKeyDirectory()),
                WalletUtils.generateKeystoreName(walletFile),
                true
        );

        assertTrue(result);
    }

    @DisplayName("json 으로 저장된 WalletFile 을 다시 역직렬화 하면 그 값은 동일하다")
    @Test
    public void serializedEqualsdeserializedWalletFileTest() throws IOException {
        String filename = WalletUtils.saveKeystore(walletFile);
        WalletFile loadedFromDisk = WalletUtils.loadKeystore(filename);

        assertEquals(walletFile.getCrypto().getCiphertext(), loadedFromDisk.getCrypto().getCiphertext());
        assertEquals(walletFile.getId(), loadedFromDisk.getId());
    }

}
