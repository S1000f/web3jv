package web3jv.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;
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

public class Web3jv {

    private final ObjectMapper mapper = new ObjectMapper();
    private String endpoint;

    public Web3jv() {
    }

    public Web3jv(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String url) {
        this.endpoint = url;
    }

    public String web3ClientVersion() throws IOException {
        return templateEmptyParams("web3_clientVersion");
    }

    public BigInteger ethBlockNumber() throws IOException {
        String result = templateEmptyParams("eth_blockNumber");
        return new BigInteger(result.substring(2), 16);
    }

    public BigDecimal ethGetBalance(String address) throws IOException {
        String result = jsonRpc(new RequestBody(
                "2.0",
                "eth_getBalance",
                Arrays.asList(address, "latest"),
                "1"
        )).getResult();
        BigInteger bigInteger = new BigInteger(result.substring(2), 16);

        return new BigDecimal(bigInteger);
    }

    public BigInteger ethGetTransactionCount(String address) throws IOException {
        String result = jsonRpc(new RequestBody(
                "2.0",
                "eth_getTransactionCount",
                Arrays.asList(address, "latest"),
                "1"
        )).getResult();

        return new BigInteger(result.substring(2), 16);
    }

    public BigInteger ethGasPrice() throws IOException {
        String result = templateEmptyParams("eth_gasPrice");
        return new BigInteger(result.substring(2), 16);
    }

    public BigInteger ethEstimateGas(String addressTo) throws IOException {
        String result = jsonRpc(new RequestBody(
                "2.0",
                "eth_estimateGas",
                Collections.singletonList(new Transaction(addressTo)),
                "1"
        )).getResult();

        return new BigInteger(result.substring(2), 16);
    }

    private <T extends RequestInterface> ResponseInterface jsonRpc(T rawBody) throws IOException {
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

    private String templateEmptyParams(String method) throws IOException {
        return jsonRpc(new RequestBody(
                "2.0",
                method,
                Collections.emptyList(),
                "1"
        )).getResult();
    }

}
