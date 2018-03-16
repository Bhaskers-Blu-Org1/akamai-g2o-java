# Akamai G2O Header Validation in Java

This is a simple library to verify Akamai signed headers.
This library does not do any direct interaction with Http headers
or runtime configuration. It should with any Java http filtering
or configuration mechanism.

Use in other applications like this:

```
import com.ibm.akamai.g2o.SignatureValidator;

// The validator can be created once and reused.
SignatureValidator validator =  SignatureValidator(....);

// Call validate for each request, passing:
//  path (or the signing string): /some/url
//  header: contents of the Akamai Data header.
//     Use SignatureValidator.AUTH_SIGNATURE_DATA_HEADER for default header name.
//  signature: contents of the Akamai signature header.
//     Use SignatureValidator.AUTH_SIGNATURE_SIGN_HEADER for default header name
VerificationResult result =  validator.validate(urlPath, header, signature);

// isValid should be obvious =)
result.isValid();

// the message will be null for valid signatures
if ( !result.isValid() ) {
  System.out.println(result.getMessage());
}
```

### Specifying parameters


Specify keys using a combined string:

```
// authNonceSecrets -- a string that is a concatenation of nonces: "key1:value1,key2:value2"
SignatureValidator validator =  SignatureValidator(authNonceSecrets);
```

or a pre-created map:

```
Map<String, String> secretMap = new HashMap<>();
secretMap.put("key1", "value1");
secretMap.put("key2", "value2");

// authNonceSecrets -- a map of key: secret
SignatureValidator validator =  SignatureValidator(secretMap);
```

### Validating the age of requests

Adjust the permitted age of requests by calling  `setTimeWindow` with a new value in seconds. The default is 30 seconds.

To make any requests older than 60 seconds invalid:

```
SignatureValidator validator =  SignatureValidator(authSecret, authNonceSecrets).setTimeWindow(60);
```

To disable this check entirely:

```
SignatureValidator validator =  SignatureValidator(authSecret, authNonceSecrets).setTimeWindow(0);
```

## Acknowledgements

This java library implementation was heavily inspired by the node `akamai-g2o` project:

https://github.com/ynohat/akamai-g2o
https://www.npmjs.com/package/akamai-g2o

