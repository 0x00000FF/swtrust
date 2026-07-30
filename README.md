# swtrust

A software TPM 2.0 for Windows, written in Rust against the TPM 2.0 Library
Specification version 185 (2026-03-12). Cryptography comes from aws-lc-rs and
its aws-lc-sys bindings.

The TPM identifies itself as manufacturer `SWT` with firmware version
`1.0.0.0`, which is what tpm.msc and similar tools display.

## Building

```
cargo build --release
```

The `prebuilt-nasm` feature of aws-lc-rs is enabled so the build does not need
NASM on the machine.

## Running

```
swtrust [OPTIONS]

  -i, --interface <socket|pipe>  Transport to listen on. Default: socket
  -a, --address <addr>           Bind address for the socket interface. Default: 127.0.0.1
  -p, --port <port>              Command port. Default: 2321. The platform
                                 control port is <port> + 1.
  -n, --pipe-name <name>         Named pipe path. Default: \\.\pipe\swtrust
  -s, --state <dir>              Directory holding the state file. Default: ./state
  -l, --log-dir <dir>            Directory for YYYY-MM-DD.log files. Default: .
  -v, --verbose                  Also print command logs to stdout
```

### Transports

`socket` speaks the TPM simulator TCP protocol: a command port and a platform
control port one above it. Existing TPM tooling connects to it without changes.
A session looks like this:

1. Connect to the platform port and send `TPM_SIGNAL_POWER_ON` and
   `TPM_SIGNAL_NV_ON`.
2. Connect to the command port, send `TPM_REMOTE_HANDSHAKE`, then
   `TPM_SEND_COMMAND` for each command.

`pipe` exposes a Windows named pipe carrying bare TPM command and response
buffers, framed by the `commandSize` and `responseSize` fields of the headers.
The pipe has no platform channel, so power is applied when the daemon starts.

### State

The non-volatile state is one hex text file, `<state-dir>/tpm-state.hex`. The
directory is created if it does not exist. The file starts with a header line
and is otherwise hex, so it can be inspected and copied with ordinary tools.
Writes go to a temporary file that is renamed over the old one, so an
interrupted save never leaves a partial state behind.

### Logs

Every command and response pair is appended to `<log-dir>/YYYY-MM-DD.log`,
named by the UTC date, with the header decoded and the full buffer in hex.
With `--verbose` the same records also go to stdout.

## Layout

```
src/
  cli.rs                 command line parsing
  logging.rs             the daily command log
  server/                transports: simulator protocol, TCP, named pipe
  tpm/
    constants.rs         Part 2 constant tables
    config.rs            implementation dependent values
    error.rs             response codes and their qualifiers
    marshal.rs           canonical big endian marshalling
    persist.rs           the hex text state file
    device.rs            the platform facing TPM
    structures/          Part 2 structures
    crypto/              hashes, HMAC, KDFs, AES, RSA, ECC, DRBG
    core/                names, PCR, hierarchies, objects, protection,
                         sessions, NV, whole TPM state
    commands/            the command table, dispatch and the commands
tests/
  end_to_end.rs          drives the TPM through real command buffers
```

## Implemented commands

Part 3 clause 9 startup and shutdown, clause 10 self test, clause 11 sessions,
clause 12.9 parameter checking, clause 14.7 curve parameters, clause 16
randomness, clause 22 integrity collection, clause 23 enhanced authorization,
clause 24 hierarchy administration, clause 25 dictionary attack functions,
clause 26 miscellaneous management, clause 28.4 context flushing, clause 30
capabilities, clause 31 NV storage, clause 36 the clock, and the vendor test
command.

## Not yet implemented

The following command groups are declared in the command table and answer
TPM_RC_COMMAND_CODE until they are written:

- object management: TPM2_Create, TPM2_CreatePrimary, TPM2_CreateLoaded,
  TPM2_Load, TPM2_LoadExternal, TPM2_ReadPublic, TPM2_Unseal,
  TPM2_ObjectChangeAuth
- cryptographic operations: TPM2_Hash, TPM2_HMAC and the hash, HMAC and event
  sequences, TPM2_Sign, TPM2_VerifySignature, TPM2_SignDigest,
  TPM2_VerifyDigestSignature, the signing and verification sequences,
  TPM2_RSA_Encrypt, TPM2_RSA_Decrypt, TPM2_ECDH_KeyGen, TPM2_ECDH_ZGen,
  TPM2_ZGen_2Phase, TPM2_ECC_Encrypt, TPM2_ECC_Decrypt, TPM2_Commit,
  TPM2_EC_Ephemeral, TPM2_EncryptDecrypt, TPM2_EncryptDecrypt2,
  TPM2_MakeCredential, TPM2_ActivateCredential, TPM2_Encapsulate,
  TPM2_Decapsulate
- attestation: TPM2_Certify, TPM2_CertifyCreation, TPM2_CertifyX509,
  TPM2_Quote, TPM2_GetTime, TPM2_GetSessionAuditDigest,
  TPM2_GetCommandAuditDigest, TPM2_NV_Certify,
  TPM2_SetCommandCodeAuditStatus
- duplication: TPM2_Duplicate, TPM2_Rewrap, TPM2_Import
- context management: TPM2_ContextSave, TPM2_ContextLoad, TPM2_EvictControl
- attached components: TPM2_AC_GetCapability, TPM2_AC_Send
- field upgrade: TPM2_FieldUpgradeStart, TPM2_FieldUpgradeData
- authenticated timers: TPM2_ACT_SetTimeout
- TPM2_SetCapability

The pieces those commands are built from are in place and tested: object slots
and naming, protected storage wrapping, deterministic RSA and ECC key
generation, the signature schemes, the KDFs and the session machinery.

## Algorithms

Hashes: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512.
Symmetric: AES with 128, 192 and 256 bit keys in CTR, OFB, CBC, CFB and ECB.
Asymmetric: RSA 1024 through 4096 with RSASSA, RSAPSS, RSAES and OAEP; ECC on
NIST P-224, P-256, P-384 and P-521 with ECDSA, ECDH, ECDAA and EC Schnorr.

NIST P-192 is not offered because the underlying library does not build that
group. SM2, SM3, SM4, Camellia, TDES, ML-KEM and ML-DSA are not implemented.
The algorithm set the TPM reports through
TPM2_GetCapability(TPM_CAP_ALGS) matches what it actually implements.

## Tests

```
cargo test
```

The unit tests check structures against the Part 2 tables and the cryptography
against published vectors: FIPS 180-4 and FIPS 202 for the hashes, RFC 2202 and
RFC 4231 for HMAC, FIPS 197 and SP800-38A for AES, and the standard curve
parameters for ECC. The integration tests drive the TPM through real command
buffers over its own interface.
