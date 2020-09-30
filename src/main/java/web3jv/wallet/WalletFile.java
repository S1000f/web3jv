package web3jv.wallet;

import com.fasterxml.jackson.annotation.JsonIgnore;
import web3jv.utils.Utils;

/**
 * <p>Keystore 저장 객체. 버전 3. <i>{@code id} 필드와 {@code WalletFile.Crypto.cipherText}</i>
 * 필드는 동일한 개인키와 비밀번호를 담고있더라도 생성시 마다 그 값이 달라지므로, 키스토어간의 비교에
 * 적합하지 않음에 유의.</p>
 * <p>키스토어 파일간의 동등비교는 오버라이딩된 {@code hashCode()} 나 {@code equals}
 * 을 사용한다.</p>
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public class WalletFile {

    private String address;
    private Crypto crypto;
    private String id;
    private int version;

    @JsonIgnore
    public String getAddressNo0x() {
        return address.startsWith("0x") ? address.substring(2) : address;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    @Override
    public String toString() {
        return "address: " + address + "\n" +
                "crypto : " + crypto + "\n" +
                "id: " + id + "\n" +
                "version: " + version;
    }

    @Override
    public int hashCode() {
        int result = Utils.generifyAddress(this.address).hashCode();
        result = 31 * result + this.version;
        result = 31 * result + this.crypto.getCipher().toLowerCase().trim().hashCode();
        result = 31 * result + this.crypto.getKdf().toLowerCase().trim().hashCode();

        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof WalletFile) {
            return this.hashCode() == obj.hashCode();
        }
        return false;
    }

    public static class Crypto {
        private String cipher;
        private String ciphertext;
        private Cipherparams cipherparams;
        private String kdf;
        private Kdfparams kdfparams;
        private String mac;

        public String getCipher() {
            return cipher;
        }

        public void setCipher(String cipher) {
            this.cipher = cipher;
        }

        public String getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(String ciphertext) {
            this.ciphertext = ciphertext;
        }

        public Cipherparams getCipherparams() {
            return cipherparams;
        }

        public void setCipherparams(Cipherparams cipherparams) {
            this.cipherparams = cipherparams;
        }

        public String getKdf() {
            return kdf;
        }

        public void setKdf(String kdf) {
            this.kdf = kdf;
        }

        public Kdfparams getKdfparams() {
            return kdfparams;
        }

        public void setKdfparams(Kdfparams kdfparams) {
            this.kdfparams = kdfparams;
        }

        public String getMac() {
            return mac;
        }

        public void setMac(String mac) {
            this.mac = mac;
        }

        @Override
        public String toString() {
            return "cipher : " + cipher + "\n" +
                    "\tciphertext : " + ciphertext + "\n" +
                    "\tcipherParams : " + cipherparams + "\n" +
                    "\tkdf : " + kdf + "\n" +
                    "\tkdfParams : " + kdfparams + "\n" +
                    "\tmac : " + mac;
        }
    }

    public static class Cipherparams {
        private String iv;

        public String getIv() {
            return iv;
        }

        public void setIv(String iv) {
            this.iv = iv;
        }

        @Override
        public String toString() {
            return "\n\t\tiv : " + this.iv;
        }
    }

    public static class Kdfparams {
        private int dklen;
        private int n;
        private int p;
        private int r;
        private String salt;

        public int getDklen() {
            return dklen;
        }

        public void setDklen(int dklen) {
            this.dklen = dklen;
        }

        public int getN() {
            return n;
        }

        public void setN(int n) {
            this.n = n;
        }

        public int getP() {
            return p;
        }

        public void setP(int p) {
            this.p = p;
        }

        public int getR() {
            return r;
        }

        public void setR(int r) {
            this.r = r;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        @Override
        public String toString() {
            return "\n\t\tdklen : " + dklen + "\n" +
                    "\t\tn : " + n + "\n" +
                    "\t\tp : " + p + "\n" +
                    "\t\tr : " + r + "\n" +
                    "\t\tsalt : " + salt;
        }
    }

}
