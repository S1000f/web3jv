package web3jv.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.Transaction;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * <p>이더리움 클라이언트의 <i>JSON-RPC</i> HTTP 통신을 랩핑한 객체. 인스턴스 생성 시,
 * 혹은 생성 후에 네트워크의 엔드포인트를 초기화 할 것. 사설 네트워크는 별도의 체인아이디 설정이
 * 필요함.</p>
 * 구현된 <i>JSON-RPC</i> 목록(geth):
 * <pre>
 *     net_version
 *     web3_clientVersion
 *     eth_blockNumber
 *     eth_getBalance
 *     eth_getTransactionCount
 *     eth_gasPrice
 *     eth_estimateGas
 *     eth_sendRawTransaction
 * </pre>
 * @see Transaction
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public class Web3jv implements Web3jvProvider {

    private final ObjectMapper mapper = new ObjectMapper();
    private String endpoint;
    private ChainIdProvider chainId;

    public Web3jv() {
    }

    public Web3jv(String endpoint, ChainIdProvider chainId) {
        this.endpoint = endpoint;
        this.chainId = chainId;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint, ChainIdProvider chainId) {
        this.endpoint = endpoint;
        this.chainId = chainId;
    }

    public ChainIdProvider getChainId() {
        return chainId;
    }

    public void setChainId(ChainIdProvider chainId) {
        this.chainId = chainId;
    }

    public String netVersion() throws IOException, JsonRpcErrorException {
        ResponseInterface result = templateEmptyParams("net_version");

        return Optional.ofNullable(result.getResult())
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public String web3ClientVersion() throws IOException, JsonRpcErrorException {
        ResponseInterface result = templateEmptyParams("web3_clientVersion");

        return Optional.ofNullable(result.getResult())
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public BigInteger ethBlockNumber() throws IOException, JsonRpcErrorException {
        ResponseInterface result = templateEmptyParams("eth_blockNumber");

        return Optional.ofNullable(result.getResult())
                .map(r -> new BigInteger(r.substring(2), 16))
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public BigDecimal ethGetBalance(String address) throws IOException, JsonRpcErrorException {
        ResponseInterface result = jsonRpc(new RequestBody(
                "2.0",
                "eth_getBalance",
                Arrays.asList(address, "latest"),
                "1"
        ));

        return Optional.ofNullable(result.getResult())
                .map(r -> new BigInteger(r.substring(2), 16))
                .map(i -> new BigDecimal(i))
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public BigInteger ethGetTransactionCount(String addressFrom) throws IOException, JsonRpcErrorException {
        ResponseInterface result = jsonRpc(new RequestBody(
                "2.0",
                "eth_getTransactionCount",
                Arrays.asList(addressFrom, "latest"),
                "1"
        ));

        return Optional.ofNullable(result.getResult())
                .map(r -> new BigInteger(r.substring(2), 16))
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public BigInteger ethGasPrice() throws IOException, JsonRpcErrorException {
        ResponseInterface result = templateEmptyParams("eth_gasPrice");
        return Optional.ofNullable(result.getResult())
                .map(r -> new BigInteger(r.substring(2), 16))
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public BigInteger ethEstimateGas(String addressTo) throws IOException, JsonRpcErrorException {
        ResponseInterface result = jsonRpc(new RequestBody(
                "2.0",
                "eth_estimateGas",
                Collections.singletonList(new Transaction(addressTo)),
                "1"
        ));

        return Optional.ofNullable(result.getResult())
                .map(r -> new BigInteger(r.substring(2), 16))
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public String ethSendRawTransaction(String signedHexString0x) throws IOException, JsonRpcErrorException {
        ResponseInterface result = jsonRpc(new RequestBody(
                "2.0",
                "eth_sendRawTransaction",
                Collections.singletonList(signedHexString0x),
                "1"
        ));

        return Optional.ofNullable(result.getResult())
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    public String ethSendRawTransaction(
            Transaction rawTx,
            String priKey,
            EncoderProvider encoder,
            List<byte[]> additional
    ) throws IOException, JsonRpcErrorException {
        ResponseInterface result = jsonRpc(new RequestBody(
                "2.0",
                "eth_sendRawTransaction",
                Collections.singletonList(rawTx.signRawTransaction(this, priKey, encoder, additional)),
                "1"
        ));

        return Optional.ofNullable(result.getResult())
                .orElseThrow(() -> new JsonRpcErrorException(result.getError().toString()));
    }

    /**
     * Http Connection 을 통해 JSON-RPC 메소드를 호출한다.
     *
     * @apiNote Json 파싱을 위해 Jackson-databind 사용
     * @param rawBody {@link RequestInterface} 구현객체 인스턴스
     * @param <T> {@link RequestInterface}
     * @return {@link ResponseInterface}
     * @throws IOException 노드와 연결이 안되거나, jackson 맵퍼가 {@code rawBody}를
     * 맵핑하지 못할 시 발생
     * @since 0.1.0
     */
    public <T extends RequestInterface> ResponseInterface jsonRpc(T rawBody) throws IOException {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; utf-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        String rawBodyString = mapper.writeValueAsString(rawBody);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = rawBodyString.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        try (BufferedReader br =
                     new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder response = new StringBuilder();
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }

            return mapper.readValue(response.toString(), ResponseBody.class);
        }
    }

    private ResponseInterface templateEmptyParams(String method) throws IOException {
        return jsonRpc(new RequestBody(
                "2.0",
                method,
                Collections.emptyList(),
                "1"
        ));
    }

    @Override
    public String toString() {
        return "endpoint : " + this.endpoint + "\n" +
                "chain id : " + this.chainId + "(" + this.chainId.toHexStringNo0x() + ")";
    }
}
