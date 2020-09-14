package web3jv.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

    public void jsonRpc(RequestBody rawBody) throws IOException {
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
            System.out.println(response.toString());
        }
    }

    public void getClientVersion() throws IOException {
        jsonRpc(new RawBody(
                "2.0",
                "web3_clientVersion",
                Collections.emptyList(),
                "1"
        ));
    }

}
