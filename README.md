# ecdsa-demo
This code snippet demonstrates how to sign data and verify the signature using ECDSA algorithm and BouncyCastle library. 
## How to run
- Open terminal and execute
        ```
        dotnet build
        dotnet run
        ```
- The snippet will create a file license.txt with signed data by a private key.
- This file will contain data and signature
- The method `ReadLicenseFromFile()` then will read the license.txt file and verify data using a public key.  