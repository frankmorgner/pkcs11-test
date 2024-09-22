# Run PKCS#11 Conformance Test Cases

`pkcs11-tool` allows running conformance test cases against a pkcs#11 provider.
The test cases were first defined in PKCS#11 version 3.1 and they include an
informal description along with a test case description given in dedicated XML
files.

`pkcs11-tool` ships with the following test cases included:
- Baseline Provider BL-M-1-31
- Extended Provider EXT-M-1-31
- Authentication Token Provider AUTH-M-1-31
- Public Certificates Token Provider CERT-M-1-31

To run the tests against your PKCS#11 module, execute the following command:
```sh
env Pin=123456 pkcs11-tool --module /path/to/pkcs11-module.so
```
The above command passes the token's PIN via the environment variable `$Pin`,
which will be used for AUTH-M-1-31. For Windows, the calling convention needs
to be adjusted as follows:
```cmd
set Pin=123456
pkcs11-tool.exe --module /path/to/pkcs11-module.dll
```

Customized test cases can be supplied behind all other arguments. This disables
the builtin test cases.
