package web3jv.jsonrpc.transaction;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.util.encoders.Hex;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.wallet.Wallet;

import java.math.BigInteger;
import java.util.Arrays;

public class Transaction {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private String v;
    private String r;
    private String s;
    private String chainId;
    private String from;

    public Transaction() {
    }

    public Transaction(String to) {
        this.to = to;
    }

    public Transaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            String r,
            String s,
            String chainId,
            String from) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        this.data = data;
        this.v = chainId;
        this.r = r;
        this.s = s;
        this.chainId = chainId;
        this.from = from;
    }

    public String signRawTransaction(Web3jvProvider web3jv, String privateKey, EncoderProvider encoder) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        ECPrivateKeyParameters priKey =
                new ECPrivateKeyParameters(new BigInteger(privateKey, 16), domain);

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priKey);

        encoder.setNonce(this.nonce);
        encoder.setGasPrice(this.gasPrice);
        encoder.setGasLimit(this.gasLimit);
        encoder.setTo(this.to);
        encoder.setValue(this.value);
        encoder.setData(this.data);
        encoder.setV(this.v);
        encoder.setR(this.r);
        encoder.setS(this.s);

        byte[] messageHash = new Keccak.Digest256().digest(encoder.encode());
        BigInteger[] sigs = signer.generateSignature(messageHash);
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignature(domain, messageHash, r, s, i);
            if (k != null && k.equals(new BigInteger(new Wallet().getPublicKey(privateKey), 16))) {
                recId = i;
                break;
            }
        }

        this.v = Integer.toHexString(recId + (Integer.parseInt(web3jv.getChainId()) * 2) + 35);
        byte[] rBytes = r.toByteArray();
        this.r = rBytes.length == 32 ? Hex.toHexString(rBytes) : Hex.toHexString(rBytes).substring(2);
        this.s = Hex.toHexString(s.toByteArray());

        encoder.setV(this.v);
        encoder.setR(this.r);
        encoder.setS(this.s);

        return "0x" + Hex.toHexString(encoder.encode());
    }

    private BigInteger recoverFromSignature(
            ECDomainParameters domain,
            byte[] messageHash,
            BigInteger r,
            BigInteger s,
            int recId
    ) {
        BigInteger n = domain.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));

        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(x, 1 + x9.getByteLength(domain.getCurve()));
        compEnc[0] = (byte) (((recId & 1) == 1) ? 0x03 : 0x02);
        ECPoint R = domain.getCurve().decodePoint(compEnc);

        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(domain.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);

        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

    /**
     * builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Transaction build = new Transaction();

        public Builder nonce(BigInteger nonce) {
            build.nonce = nonce;
            return this;
        }

        public Builder gasPrice(BigInteger gasPrice) {
            build.gasPrice = gasPrice;
            return this;
        }

        public Builder gasLimit(BigInteger gasLimit) {
            build.gasLimit = gasLimit;
            return this;
        }

        public Builder to(String hexStringNo0x) {
            build.to = hexStringNo0x;
            return this;
        }

        public Builder value(BigInteger value) {
            build.value = value;
            return this;
        }

        public Builder data(String hexStringNo0x) {
            build.data = hexStringNo0x;
            return this;
        }

        public Builder v(String hexStringNo0x) {
            build.v = hexStringNo0x;
            return this;
        }

        public Builder r(String hexStringNo0x) {
            build.r = hexStringNo0x;
            return this;
        }

        public Builder s(String hexStringNo0x) {
            build.s = hexStringNo0x;
            return this;
        }

        public Builder chainId(String hexStringNo0x) {
            build.chainId = hexStringNo0x;
            return this;
        }

        public Builder from(String hexStringNo0x) {
            build.from = hexStringNo0x;
            return this;
        }

        public Transaction build() {
            return build;
        }
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String hexStringNo0x) {
        this.from = hexStringNo0x;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String hexStringNo0x) {
        this.to = hexStringNo0x;
    }

    public BigInteger getGasLimit() {
        return gasLimit;
    }

    public void setGasLimit(BigInteger gasLimit) {
        this.gasLimit = gasLimit;
    }

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public void setGasPrice(BigInteger gasPrice) {
        this.gasPrice = gasPrice;
    }

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public String getData() {
        return data;
    }

    public void setData(String hexStringNo0x) {
        this.data = hexStringNo0x;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String hexStringNo0x) {
        this.chainId = hexStringNo0x;
    }

    public String getV() {
        return v;
    }

    public void setV(String hexStringNo0x) {
        this.v = hexStringNo0x;
    }

    public String getR() {
        return r;
    }

    public void setR(String hexStringNo0x) {
        this.r = hexStringNo0x;
    }

    public String getS() {
        return s;
    }

    public void setS(String hexStringNo0x) {
        this.s = hexStringNo0x;
    }
}
