# Run PKCS#11 Conformance Test Cases

`pkcs11-test` allows running conformance test cases against a pkcs#11 provider.
The test cases were first defined in PKCS#11 version 3.1 and they include an
informal description along with a test case description given in dedicated XML
files.

`pkcs11-test` ships with the following test cases included:
- [Baseline Provider](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html#_Toc142307335) [BL-M-1-31](src/test-cases/pkcs11-v3.1/mandatory/BL-M-1-31.xml)
- [Extended Provider](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html#_Toc142307339) [EXT-M-1-31](src/test-cases/pkcs11-v3.1/mandatory/EXT-M-1-31.xml)
- [Authentication Token Provider](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html#_Toc142307342) [AUTH-M-1-31](src/test-cases/pkcs11-v3.1/mandatory/AUTH-M-1-31.xml)
- [Public Certificates Token Provider](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html#_Toc142307345) [CERT-M-1-31](src/test-cases/pkcs11-v3.1/mandatory/CERT-M-1-31.xml)

To run the tests against your PKCS#11 module, execute the following command:
```sh
env Pin=123456 pkcs11-test --module /path/to/pkcs11-module.so
```
The above command passes the token's PIN via the environment variable `$Pin`,
which will be used for AUTH-M-1-31. For Windows, the calling convention needs
to be adjusted as follows:
```cmd
set Pin=123456
pkcs11-test.exe --module /path/to/pkcs11-module.dll
```

Customized test cases can be supplied behind all other arguments. This disables
the builtin test cases.

## Supports Functions

[ ] `C_CloseAllSessions`
[x] `C_CloseSession`
[x] `C_Finalize`
[x] `C_FindObjects`
[x] `C_FindObjectsFinal` (`C_FindObjectsFinal` is executed after each call of `C_FindObjects` and cannot be triggered seperately.)
[x] `C_FindObjectsInit` (`C_FindObjectsInit` is executed before each call of `C_FindObjects` and cannot be triggered seperately.)
[x] `C_GetAttributeValue`
[x] `C_GetInfo`
[x] `C_GetMechanismInfo`
[x] `C_GetMechanismList`
[x] `C_GetSlotInfo`
[x] `C_GetSlotList`
[x] `C_GetTokenInfo`
[x] `C_Initialize`
[x] `C_Login`
[x] `C_Logout`
[x] `C_OpenSession`
[x] `C_Sign`
[x] `C_SignInit` (`C_SignInit` is executed before each call of `C_Sign` and cannot be triggered seperately.)

## Build `pkcs11-test`

```sh
cargo build
```
