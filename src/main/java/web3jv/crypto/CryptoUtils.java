package web3jv.crypto;

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
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import web3jv.jsonrpc.transaction.DecoderProvider;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.Transaction;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;

import java.math.BigInteger;
import java.util.Arrays;

public class CryptoUtils {

    private static final String ETHEREUM_SPEC = "\u0019Ethereum Signed Message:\n";

    public static String getKeccack256HexString(String publicKey) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        byte[] bytes = ByteUtils.fromHexString(publicKey); // keccak = 제로패딩 없어야 함

        return Hex.toHexString(keccak.digest(bytes));
    }

    public static String getKeccack256HexString(byte[] input) {
        return Hex.toHexString(getKeccack256Bytes(input));
    }

    public static byte[] getKeccack256Bytes(byte[] input) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        return keccak.digest(input);
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션의 객체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @param <T> extends {@link Transaction}
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static <T extends Transaction> boolean validateSignedTx(
            T receivedTx,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

        encoder.setNonce(receivedTx.getNonce());
        encoder.setGasPrice(receivedTx.getGasPrice());
        encoder.setGasLimit(receivedTx.getGasLimit());
        encoder.setTo(receivedTx.getTo());
        encoder.setValue(receivedTx.getValue());
        encoder.setData(receivedTx.getData());
        encoder.setV(chainId);
        encoder.setR("");
        encoder.setS("");
        byte[] messageHash = getKeccack256Bytes(encoder.encode());

        BigInteger r = new BigInteger(receivedTx.getR(), 16);
        BigInteger s = new BigInteger(receivedTx.getS(), 16);

        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && Wallet.getAddressNo0x(Utils.toHexStringNo0x(k.toByteArray()))
                    .equals(Utils.generifyAddress(address))) {
                return true;
            }
        }

        return false;
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션
     * @param decoder 수신한 트랜젝션에 사용된 디코더 객체 혹은 그 디코딩 체계의 구현체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static boolean validateSignedTx(
            byte[] receivedTx,
            DecoderProvider decoder,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        return validateSignedTx(decoder.decode(receivedTx), encoder, address, chainId);
    }

    /**
     * <p>수신한 트랜젝션의 서명을 검증한다.</p>
     * @param receivedTx 수신한 트랜젝션
     * @param decoder 수신한 트랜젝션에 사용된 디코더 객체 혹은 그 디코딩 체계의 구현체
     * @param encoder 수신한 트랜젝션에 사용된 인코더 객체 혹은 그 인코딩 체계의 구현체
     * @param address 검증에 사용 될 송신자 주소. '0x' 여부 상관없이 입력.
     * @param chainId 사용된 네트워크의 체인아이디
     * @return 수신한 트랜젝션이 유효한 서명을 가진경우 참 반환.
     * @since 0.1.0
     */
    public static boolean validateSignedTx(
            String receivedTx,
            DecoderProvider decoder,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        return validateSignedTx(decoder.decode(receivedTx), encoder, address, chainId);
    }

    public static BigInteger[] signMessageByECDSA(byte[] targetMessage, String HexPassword) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        ECPrivateKeyParameters priKey =
                new ECPrivateKeyParameters(new BigInteger(HexPassword, 16), domain);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priKey);

        byte[] messageHash = getKeccack256Bytes(targetMessage);

        BigInteger[] sigs = signer.generateSignature(messageHash);
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        return new BigInteger[] {r, s};
    }

    public static BigInteger recoverFromSignedMessage(
            ECNamedCurveParameterSpec params,
            byte[] messageHash,
            BigInteger r,
            BigInteger s,
            int recId
    ) {
        BigInteger n = params.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(x, 1 + x9.getByteLength(params.getCurve()));
        compEnc[0] = (byte) (((recId & 1) == 1) ? 0x03 : 0x02);
        ECPoint R = params.getCurve().decodePoint(compEnc);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(params.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);

        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

    public static String signMessageByEthSpec(String privateKey, String message) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

        String applied = ETHEREUM_SPEC + message.length() + message;
        byte[] messageHash = CryptoUtils.getKeccack256Bytes(Utils.toBytes(applied));

        BigInteger[] sigs = CryptoUtils.signMessageByECDSA(Utils.toBytes(applied), privateKey);
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = CryptoUtils.recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null && k.equals(new BigInteger(Wallet.getPublicKey(privateKey), 16))) {
                recId = i;
                break;
            }
        }

        String v = Integer.toHexString(recId + 25);
        byte[] rBytes = r.toByteArray();
        String stringR = rBytes.length == 32 ? Hex.toHexString(rBytes) : Hex.toHexString(rBytes).substring(2);
        String stringS = Hex.toHexString(s.toByteArray());

        String signature = stringR + stringS + v;

        return "0x" + signature;
    }

}

