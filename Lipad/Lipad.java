package Lipad;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


import org.json.JSONException;
import org.json.JSONObject;

public class Lipad {
    private static final Logger LOGGER = Logger.getLogger(Lipad.class.getName());
    private final String IVKey;
    private final String consumerSecret;
    private final String consumerKey;
    private final String environment;

    private static final String CHECKOUT_BASE_URL_PROD = "https://api.lipad.io/api/v1";
    private static final String CHECKOUT_BASE_URL_SANDBOX = "https://checkout.uat.lipad.io/api/v1";
    private static final String DIRECT_CHARGE_BASE_URL_PROD = "https://charge.lipad.io/v1";
    private static final String DIRECT_CHARGE_BASE_URL_SANDBOX = "https://dev.charge.lipad.io/v1";
    private static final String DIRECT_API_AUTH_URL_PROD = "https://api.lipad.io/v1/auth";
    private static final String DIRECT_API_AUTH_URL_SANDBOX = "https://dev.lipad.io/v1/auth";

    public Lipad(String IVKey, String consumerSecret, String consumerKey, String environment) {
        this.IVKey = IVKey;
        this.consumerSecret = consumerSecret;
        this.consumerKey = consumerKey;
        this.environment = environment;
    }

    public String encrypt(String payload) throws Exception {
        byte[] secretBytes = sha256(consumerSecret).substring(0, 32).getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretBytes, "AES");

        byte[] IVBytes = sha256(IVKey).substring(0, 16).getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(IVBytes);

        String algorithm = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();

        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public void validatePayload(String payload) throws Exception {
        String[] requiredKeys = {
                "msisdn",
                "account_number",
                "country_code",
                "currency_code",
                "client_code",
                "due_date",
                "customer_email",
                "customer_first_name",
                "customer_last_name",
                "merchant_transaction_id",
                "preferred_payment_option_code",
                "callback_url",
                "request_amount",
                "request_description",
                "success_redirect_url",
                "fail_redirect_url",
                "invoice_number",
                "language_code",
                "service_code",
                //Optional params
                // "preferred_payment_option_code",
                // "invoice_number",
                // "language_code",
        };
        payload = payload.replaceAll("\\s+", "");


        for (String key : requiredKeys) {
            if (!payload.contains("\"" + key + "\":")) {
                throw new Exception("Missing required key: " + key);
            }
        }
    }

    private JSONObject getAccessToken(String consumerKey, String consumerSecret) throws Exception {
        String apiUrl = environment.equals("production") ? DIRECT_API_AUTH_URL_PROD : DIRECT_API_AUTH_URL_SANDBOX;

        URI uri = new URI(apiUrl);
        URL url = uri.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        String requestBody = "consumer_key=" + URLEncoder.encode(consumerKey, StandardCharsets.UTF_8) +
                "&consumer_secret=" + URLEncoder.encode(consumerSecret, StandardCharsets.UTF_8);

        connection.setDoOutput(true);
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = requestBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_CREATED) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                JSONObject jsonResponse = new JSONObject(response.toString());
                System.out.println(jsonResponse);
                return jsonResponse;
            }
        } else if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            System.out.println("Invalid Credentials!");
            throw new Exception("Invalid Credentials");
        } else {
            throw new Exception("Failed to retrieve access token. Response code: " + responseCode);
        }
    }

    private String getCheckoutStatus(String merchant_transaction_id, String access_token) throws Exception {
        String apiUrl = environment.equals("production") ? STR."\{CHECKOUT_BASE_URL_PROD}/checkout/request/status?merchant_transaction_id=" :
                STR."\{CHECKOUT_BASE_URL_SANDBOX}/checkout/request/status?merchant_transaction_id=";

        apiUrl += URLEncoder.encode(merchant_transaction_id, StandardCharsets.UTF_8);


        URI uri = new URI(apiUrl);
        URL url = uri.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + access_token);


        System.out.println("Request URL: " + url);
        System.out.println("Request Method: " + connection.getRequestMethod());
        System.out.println("Authorization: Bearer " + access_token);



        int responseCode = connection.getResponseCode();
        System.out.println(STR."Response Code Received: \{responseCode}");
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                System.out.println(response);
                LOGGER.info(STR."Checkout Status Response: \{response.toString()}");
                return response.toString();
            }
        } else if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            System.out.println("Unauthorized");
            throw new Exception("Unauthorized");
        } else {
            throw new Exception("Failed to retrieve checkout status. Response code: " + responseCode);
        }
    }
    public JSONObject checkCheckoutStatus(String merchant_transaction_id) {
        try {
            JSONObject accessTokenResponse = getAccessToken(consumerKey, consumerSecret);
            String accessToken = accessTokenResponse.optString("access_token");
            String checkoutStatusResponse = getCheckoutStatus(merchant_transaction_id, accessToken);
            return new JSONObject(checkoutStatusResponse);
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, STR."Error parsing JSON response: \{e.getMessage()}", e);
            throw new RuntimeException(STR."Error parsing JSON response: \{e.getMessage()}");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, STR."Error checking checkout status: \{e.getMessage()}", e);
            throw new RuntimeException(STR."Error checking checkout status: \{e.getMessage()}");
        }
    }


//    public JSONObject checkCheckoutStatus(String merchant_transaction_id) throws Exception {
//        JSONObject accessTokenResponse = getAccessToken(consumerKey, consumerSecret);
//        String accessToken = accessTokenResponse.optString("access_token");
//        String checkoutStatusResponse = getCheckoutStatus(merchant_transaction_id, accessToken);
//        return new JSONObject(checkoutStatusResponse);
//    }

    public void directCharge(String payload, String consumerKey, String consumerSecret) {
        try {
            String baseUrl = environment.equals("production") ? DIRECT_CHARGE_BASE_URL_PROD + "?payment_method=" : DIRECT_CHARGE_BASE_URL_SANDBOX + "?payment_method=";
            JSONObject accessTokenResponse;
            try {
                accessTokenResponse = getAccessToken(consumerKey, consumerSecret);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error in getAccessToken", e);
                return;
            }

            String accessToken = accessTokenResponse.optString("access_token");
            LOGGER.info("Access Token: " + accessToken);

            JSONObject paymentPayload = new JSONObject(payload);

            Map<String, String> paymentMethodMap = new HashMap<>();
            paymentMethodMap.put("MPESA_KEN", "mpesa");
            paymentMethodMap.put("AIRTEL_KEN", "airtel_money");

            String paymentMethodCode = paymentPayload.optString("payment_method_code");
            String endpoint = paymentMethodCode != null ? paymentMethodMap.get(paymentMethodCode) : null;

            if (endpoint != null && !endpoint.isEmpty()) {
                String url = baseUrl + endpoint;
                LOGGER.info("Endpoint: " + url);

                Map<String, Object> response = postRequest(url, buildPaymentPayload(paymentPayload), accessToken);
                LOGGER.info("Response: " + response);

            } else {
                throw new Exception("Invalid payment method code: " + paymentPayload.optString("payment_method_code"));
            }
        } catch (Exception error) {
            LOGGER.log(Level.SEVERE, "Error: " + error.getMessage(), error);
        }
    }

//    private JSONObject buildPaymentPayload(@org.jetbrains.annotations.NotNull JSONObject payload) {
private JSONObject buildPaymentPayload(JSONObject payload) {
        JSONObject commonPayload = new JSONObject();
        commonPayload.put("external_reference", payload.opt("external_reference"));
        commonPayload.put("origin_channel_code", "API");
        commonPayload.put("originator_msisdn", payload.opt("originator_msisdn"));
        commonPayload.put("payer_msisdn", payload.opt("payer_msisdn"));
        commonPayload.put("service_code", payload.opt("service_code"));
        commonPayload.put("account_number", payload.opt("account_number"));
        commonPayload.put("client_code", payload.opt("client_code"));
        commonPayload.put("payer_email", payload.opt("payer_email"));
        commonPayload.put("country_code", payload.opt("country_code"));
        commonPayload.put("invoice_number", payload.opt("invoice_number"));
        commonPayload.put("currency_code", payload.opt("currency_code"));
        commonPayload.put("amount", payload.opt("amount"));
        commonPayload.put("add_transaction_charge", payload.opt("add_transaction_charge"));
        commonPayload.put("transaction_charge", payload.opt("transaction_charge"));
        commonPayload.put("extra_data", payload.opt("extra_data"));
        commonPayload.put("description", "Payment by " + payload.opt("payer_msisdn"));
        commonPayload.put("notify_client", payload.opt("notify_client"));
        commonPayload.put("notify_originator", payload.opt("notify_originator"));

        JSONObject mpesaPayload = new JSONObject(commonPayload, JSONObject.getNames(commonPayload));
        mpesaPayload.put("payment_method_code", "MPESA_KEN");
        mpesaPayload.put("paybill", payload.opt("paybill"));

        JSONObject airtelPayload = new JSONObject(commonPayload, JSONObject.getNames(commonPayload));
        airtelPayload.put("payment_method_code", "AIRTEL_KEN");

        JSONObject resultPayload = "MPESA_KEN".equals(payload.opt("payment_method_code")) ? mpesaPayload : airtelPayload;
        System.out.println("Built Payload: " + resultPayload);
        return "MPESA_KEN".equals(payload.opt("payment_method_code")) ? mpesaPayload : airtelPayload;
    }

    private Map<String, Object> postRequest(String url, JSONObject data, String accessToken) {
        try {
            URI uri = new URI(url);
            HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
            connection.setRequestMethod("POST");

            System.out.println("Access Token in Header: " + accessToken);

            connection.setRequestProperty("x-access-token", accessToken);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            System.out.println("Sending POST request to: " + url);
            System.out.println("Request Body: " + data.toString());

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = data.toString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_CREATED) {
                try (InputStream inputStream = connection.getInputStream()) {

                    System.out.println("Received successful response.");
                    return handleResponse(inputStream);
                }
            } else {
                System.out.println("Failed to make POST request. Response code: " + responseCode);

                throw new Exception("Failed to make POST request. Response code: " + responseCode);
            }
        } catch (IOException e) {
            System.out.println("Failed to make POST request: " + e.getMessage());

            throw new RuntimeException("Failed to make POST request: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Error processing POST response: " + e.getMessage());

            throw new RuntimeException("Error processing POST response: " + e.getMessage());
        }
    }

    private Map<String, Object> handleResponse(InputStream inputStream) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            StringBuilder responseStringBuilder = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                responseStringBuilder.append(line);
            }
            return new JSONObject(responseStringBuilder.toString()).toMap();
        }
    }

    public Map<String, Object> getChargeRequestStatus(String chargeRequestId, String consumerKey, String consumerSecret) {
        try {
            JSONObject accessTokenResponse;
            try {
                accessTokenResponse = getAccessToken(consumerKey, consumerSecret);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error in getAccessToken", e);
                throw new RuntimeException("Failed to get access token.", e);
            }

            String accessToken = accessTokenResponse.optString("access_token");

            HttpURLConnection connection = getHttpURLConnection(chargeRequestId, accessToken);

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    StringBuilder responseStringBuilder = new StringBuilder();
                    String line;
                    while ((line = in.readLine()) != null) {
                        responseStringBuilder.append(line);
                    }

                    return new JSONObject(responseStringBuilder.toString()).toMap();
                }
            } else {
                LOGGER.log(Level.SEVERE, "Failed to make GET request. Response code: " + responseCode);
                throw new RuntimeException("Failed to make GET request. Response code: " + responseCode);
            }
        } catch (IOException | java.net.URISyntaxException e) {
            LOGGER.log(Level.SEVERE, "Failed to make GET request: " + e.getMessage(), e);
            throw new RuntimeException("Failed to make GET request: " + e.getMessage());
        }
    }

    private HttpURLConnection getHttpURLConnection(String chargeRequestId, String accessToken) throws URISyntaxException, IOException {
        String baseUrl = environment.equals("production") ? DIRECT_CHARGE_BASE_URL_PROD + "/transaction/" : DIRECT_CHARGE_BASE_URL_SANDBOX + "/transaction/";
        baseUrl += chargeRequestId + "/status";

        URI uri = new URI(baseUrl);
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("x-access-token", accessToken);
        connection.setRequestProperty("Content-Type", "application/json");
        return connection;
    }
}
