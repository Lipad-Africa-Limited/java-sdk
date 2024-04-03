# Lipad Java SDK

## Introduction

The Lipad Java SDK facilitates the integration of Lipad's Direct API and Checkout features into your Java applications. This comprehensive guide will assist you in the setup and utilization of the Lipad SDK.

## Prerequisites

Before getting started, ensure you have the following:

- Ensure that you have installed JDK. JDK is available for various operating systems such as Windows, macOS, and Linux.
- Lipad API credentials, including the IV Key, Consumer Secret, Consumer Key.
- Environment: Decide whether you want to work in the production or sandbox environment. Lipad provides different URLs for each environment, so choose accordingly.

## Installation

1. **Download the Lipad SDK:**
   Download the Lipad SDK and include it in your project.

   ```bash
   # Example using pip
   pip install lipad-sdk

2. **Import the Lipad class and necessary libraries:**

    ```bash
   from lipad import Lipad
   import json
   import ayncio

3. **Create an asynchronous main function.**

    ```bash
   async def main():

    // Replace these values with your actual credentials
    iv_key = "your_iv_key";
    consumer_secret = "your_consumer_secret";
    consumer_key = "your_consumer_key"
    environment = "sandbox", "production";
    charge_request_id = "your_charge_request_id"

4. **Running the script**
   ### To execute the script and run the main function, add the following line at the end of your script:

    ```bash
   if __name__ == "__main__":
    asyncio.run(main())

## Checkout Usage

1. **To initialize the Lipad class, provide the iv_key, consumer_key, consumer_secret, and environment parameters. The environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
   lipad = new Lipad(iv_key, consumer_key, consumer_secret, environment);

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
            lipad.validate_payload(payload)

3. **Convert payload to JSON String and encrypt Payload**

    ```bash
    payload_json_string = json.dumps(payload)
    encrypted_payload = checkout.encrypt(payload_json_string)
    print("Encrypted Payload:", encrypted_payload)

4. **Get Checkout Status**

    ```bash
    merchant_transaction_id = payload.get("merchant_transaction_id")
    print("Merchant Transaction ID:", merchant_transaction_id)
   
    checkout_data = await checkout.check_checkout_status(merchant_transaction_id)
    print("Checkout Data:", checkout_data)

5. **Build Checkout URL**

    ```bash
    checkout_url = f"https://checkout2.dev.lipad.io/?access_key={access_key}&payload={encrypted_payload}"
    print("Checkout URL:", checkout_url)

## Direct API Usage

1. **To initialize the Lipad class, provide the iv_key, consumer_key, consumer_secret, and environment parameters. The environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
    lipad = new Lipad(iv_key, consumer_key, consumer_secret, environment);

2. **Direct Charge**

    ```bash
    await lipad.direct_charge(json.dumps(payload))

3. **Get Charge Request Status**

    ```bash
    checkout_request_status = await checkout.get_charge_request_status(
    chargeRequestId
    )
    print("Checkout Request Status", checkout_request_status)

# License

## This SDK is open-source and available under the MIT License. 
