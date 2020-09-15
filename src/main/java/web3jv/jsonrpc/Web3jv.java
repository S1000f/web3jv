package web3jv.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
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

    public void setEndpoint(String url) {
        this.endpoint = url;
    }

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

    public ResponseInterface getClientVersion() throws IOException {
        return jsonRpc(new RequestBody(
                "2.0",
                "web3_clientVersion",
                Collections.emptyList(),
                "1"
        ));
    }

    public BigInteger getBalance(String address) throws IOException {

        String result = jsonRpc(new RequestBody(
                "2.0",
                "eth_getBalance",
                Arrays.asList(address, "latest"),
                "1"
        )).getResult();

        return new BigInteger(result.substring(2), 16);
    }

}