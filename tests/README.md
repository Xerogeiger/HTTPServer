# Test Certificates

This folder contains sample TLS certificates used by the project. The script
`generate_localhost_cert.sh` can be used to create a self-signed certificate and
matching key suitable for development.

Run the script from this directory:

```sh
sh generate_localhost_cert.sh
```

The resulting files `localhost_cert.pem` and `localhost_key.pem` will appear in
the same folder. Both the certificate's Common Name and Subject Alternative Name
are set to `localhost` so browsers will not warn about mismatched host names.
