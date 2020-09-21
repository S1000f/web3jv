package web3jv.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * <p>키스토어 파일의 생성 및 관리에 대한 유틸리티 모음. <i>WalletFile</i> 을
 * 직렬화하여 json 형태의 파일로 저장한다.</p>
 * <p>기본적으로 제공되는 경로와 파일명을 사용 할 수 있으며, 필요시 직접
 * 경로와 파일명을 지정할 수 있다.</p>
 * @see WalletFile
 * @see Wallet
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public class WalletUtils {

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * <p>지정된 경로와 이름으로 키스토어 파일을 저장한다.</p>
     * @param walletFile 키스토어 파일을 만들 WalletFile 객체
     * @param directory 저장할 경로
     * @param filename 저장할 파일이름
     * @param createDirectory 저장할 경로가 없는 경우 해당 디렉토리 생성여부 결정
     * @param <T> WalletFile 혹은 상속하는 객체
     * @return 생성 성공시 true 반환
     * @throws IOException 지정된 경로에 접근할 수 없거나 파일생성에 실패한 경우 발생
     * @since 0.1.0
     */
    public static <T extends WalletFile> boolean saveKeystore(
            T walletFile,
            Path directory,
            String filename,
            boolean createDirectory
    ) throws IOException {
        String jsonString = mapper.writeValueAsString(walletFile);

        if (createDirectory && Files.notExists(directory)) {
            Files.createDirectory(directory);
        }
        Path filePath = Paths.get(directory + File.separator + filename);
        try (BufferedWriter bw = Files.newBufferedWriter(filePath)) {
            bw.write(jsonString, 0, jsonString.length());
        }

        return Files.isReadable(filePath);
    }

    /**
     * <p>WalletFile 을 기본경로에 기본 파일명으로 저장한다. 파일형식은 json 이다.</p>
     * @param walletFile 키스토어 파일을 만들 객체
     * @param <T> WalletFile 혹은 상속하는 객체
     * @return 저장된 키스토어 파일의 이름
     * @throws IOException 기본경로에 접근하거나 생성할 수 없을때 발생
     * @see WalletUtils#getDefaultKeyDirectory()
     * @see WalletUtils#generateKeystoreName(WalletFile)
     * @since 0.1.0
     */
    public static <T extends WalletFile> String saveKeystore(T walletFile) throws IOException {
        String filename = generateKeystoreName(walletFile);
        saveKeystore(walletFile, Paths.get(getDefaultKeyDirectory()), filename, true);

        return filename;
    }

    /**
     * <p>지정된 경로에 있는 지정된 이름의 키스토어 파일을 <i>WalletFile</i> 객체로
     * 생성하여 반환한다.</p>
     * @param directory 키스토어 파일이 위치한 경로
     * @param filename 키스토어 파일 이름
     * @return WalletFile 객체
     * @throws IOException 지정한 경로에 접근할 수 없거나 존재하지 않는 경우 발생
     * @see WalletFile
     * @see WalletUtils#loadKeystore(String)
     * @since 0.1.0
     */
    public static WalletFile loadKeystore(Path directory, String filename) throws IOException {
        return mapper.readValue(Paths.get(directory + File.separator + filename).toFile(), WalletFile.class);
    }

    /**
     * <p>기본저장 경로에 위치한 지정된 이름의 키스토어 파일을
     * <i>WalletFile</i> 객체로 생성하여 반환한다.</p>
     * @param filename 키스토어 파일 이름
     * @return WalletFile 객체
     * @throws IOException 경로에 접근할 수 없거나 존재하지 않는 경우 발생
     * @see WalletFile
     * @see WalletUtils#loadKeystore(Path, String)
     * @since 0.1.0
     */
    public static WalletFile loadKeystore(String filename) throws IOException {
        return loadKeystore(Paths.get(getDefaultKeyDirectory()), filename);
    }

    /**
     * <p>운영체제별로 정해진 기본 키스토어 파일 저장경로를 반환한다.</p>
     * 기본경로:
     * <pre>
     *     윈도우: C:\Users\유저이름\AppData\Roaming\Ethereum
     *     맥: /Users/유저이름/Library/Ethereum
     *     유닉스/리눅스: /home/유저이름/.ethereum
     * </pre>
     * @return String 기본 저장 경로
     * @since 0.1.0
     */
    public static String getDefaultKeyDirectory() {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("mac")) {
            return System.getProperty("user.home") + File.separator + "Library" + File.separator + "Ethereum";
        } else if (osName.startsWith("win")){
            return System.getenv("APPDATA") + File.separator + "Ethereum";
        } else {
            return System.getProperty("user.home") + File.separator + ".ethereum";
        }
    }

    /**
     * <p>키스토어 파일의 이름을 생성한다. 이름만 생성하여 반환하며,
     * 파일의 저장은 별도의 메소드로 수행하여야 한다.</p>
     * 파일명 형식:
     * <pre>
     *     UTC--yyyy-MM-ddTHH-mm-ss.nVV--입력한주소.json
     * </pre>
     * @param walletFile 생성할 키스토어 이름에 추가될 주소가 담긴 객체
     * @return 키스토어 이름. 입력한 주소가 같더라도 이름은 매 나노초 마다 바뀌므로 유의한다.
     * @see WalletUtils#saveKeystore(WalletFile)
     * @since 0.1.0
     */
    public static <T extends WalletFile> String generateKeystoreName(T walletFile) {
        DateTimeFormatter format = DateTimeFormatter.ofPattern("'UTC--'yyyy-MM-dd'T'HH-mm-ss.nVV'--'");
        return ZonedDateTime.now(ZoneOffset.UTC).format(format) + walletFile.getAddress() + ".json";
    }

    /**
     * <p>키스토어 파일의 이름을 생성한다. 이름만 생성하여 반환하며,
     * 파일의 저장은 별도의 메소드로 수행하여야 한다.</p>
     * 파일명 형식:
     * <pre>
     *      UTC--yyyy-MM-ddTHH-mm-ss.nVV--입력한주소.json
     * </pre>
     * @param address '0x' 없는 주소
     * @return String 키스토어 이름. 입력한 주소가 같더라도 이름은 매 나노초 마다 바뀌므로 유의한다.
     * @see WalletUtils#saveKeystore(WalletFile)
     * @see WalletUtils#generateKeystoreName(WalletFile)
     * @since 0.1.0
     */
    public static String generateKeystoreName(String address) {
        DateTimeFormatter format = DateTimeFormatter.ofPattern("'UTC--'yyyy-MM-dd'T'HH-mm-ss.nVV'--'");
        return ZonedDateTime.now(ZoneOffset.UTC).format(format) +
                (address.startsWith("0x") ? address.substring(2) : address) +
                ".json";
    }

}
