# Lipad Java SDK

## Introduction

The Lipad Java SDK facilitates the integration of Lipad's Direct API and Checkout features into your Java applications. This comprehensive guide will assist you in the setup and utilization of the Lipad SDK.

## Prerequisites

Before getting started, ensure you have the following:

- Ensure that you have installed JDK. JDK is available for various operating systems such as Windows, macOS, and Linux.
- Lipad API credentials, including the IV Key, Consumer Secret, Consumer Key.
- Environment: Decide whether you want to work in the production or sandbox environment. Lipad provides different URLs for each environment, so choose accordingly.

## Installation

1. **Import the Lipad class:**

    ```bash
   package ConsumerCheckout;
   import Lipad.Lipad;

2. **Create a Main function.**

    ```bash
   public class Main {
    public static void main(String[] args) {
        String IVKey = <your_IVKey>;
        String consumerSecret = <your_consumerKey>;
        String consumerKey = <your_consumerKey>;
        String chargeRequestId = <charge_request_id>;
        String environment = <sandbox/production>;
     }
   }

## Checkout Usage

1. **To initialize the Lipad class, provide the IVKey, consumerKey, consumerSecret, and environment parameters. The environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
   Lipad encryption = new Lipad(IVKey, consumerSecret, consumerKey, environment);

2. **Validate Payload**

       ```bash
       payload = {
           "msisdn": "",
           "account_number": "",
           "country_code": "",
           "currency_code": "",
           "client_code": "",
           "due_date": "",
           "customer_email": "",
           "customer_first_name": "",
           "customer_last_name": "",
           "merchant_transaction_id": "",
           "preferred_payment_option_code": "",
           "callback_url": "",
           "request_amount": "",
           "request_description": "",
           "success_redirect_url": "",
           "fail_redirect_url": "",
           "invoice_number": "",
           "language_code": "en",
           "service_code": "",
       }
            encryption.validatePayload(payload);

3. **Encrypt Payload**

    ```bash
    String encryptedPayload = encryption.encrypt(payload);

4. **Extract Merchant transaction ID & Get Checkout Status**

    ```bash
    int startIndex = payload.indexOf("\"merchant_transaction_id\": \"") + "\"merchant_transaction_id\": \"".length();
    int endIndex = payload.indexOf("\"", startIndex);
    String merchant_transaction_id = payload.substring(startIndex, endIndex);
   
    JSONObject checkoutStatusJSON = encryption.checkCheckoutStatus(merchant_transaction_id);
    System.out.println(STR."Checkout Status JSON: \{checkoutStatusJSON}");

5. **Build & log Checkout URL**

    ```bash
    String accessKey = <your_accessKey>;
    String checkoutUrl = STR."https://checkout.dev.lipad.io/?access_key=\{encodeURIComponent(accessKey)}&payload=\{encodeURIComponent(encryptedPayload)}";
    System.out.println(STR."Checkout URL: \{checkoutUrl}");
   

## Direct API Usage

1. **To initialize the Lipad class, provide the IVKey, consumerKey, consumerSecret, and environment parameters. The environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
    Lipad encryption = new Lipad(IVKey, consumerSecret, consumerKey, environment);

2. **Direct Charge**

    ```bash
    encryption.directCharge(payload, consumerKey, consumerSecret);

3. **Get Charge Request Status**

    ```bash
    Map<String, Object> result = encryption.getChargeRequestStatus(chargeRequestId, consumerKey, consumerSecret);
    System.out.println(result);

# License

## This SDK is open-source and available under the MIT License. 
