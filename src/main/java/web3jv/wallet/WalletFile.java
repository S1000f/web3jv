package web3jv.wallet;

public class WalletFile {

    private String address;
    private Crypto crypto;
    private String id;
    private int version;

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

    public static class Crypto {
        private String cipher;
        private String ciphertext;
        private Cipherparams cipherParams;
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

        public Cipherparams getCipherParams() {
            return cipherParams;
        }

        public void setCipherParams(Cipherparams cipherParams) {
            this.cipherParams = cipherParams;
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
    }

    public static class Cipherparams {
        private String iv;

        public String getIv() {
            return iv;
        }

        public void setIv(String iv) {
            this.iv = iv;
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
    }

}
