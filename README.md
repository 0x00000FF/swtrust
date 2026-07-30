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

All 135 commands in the table are dispatched. 134 carry out their operation;
TPM2_CertifyX509 is dispatched but answers TPM_RC_COMMAND_CODE because
building and re-encoding a partial X.509 certificate is not implemented.

By clause:

- clause 9 startup and shutdown, clause 10 self test
- clause 11 sessions and clause 23 enhanced authorization, every policy
  assertion
- clause 12 object management, including credentials
- clause 13 duplication: duplicate, rewrap and import, with the inner and
  outer wraps of Part 1 clause 23
- clause 14 asymmetric primitives: RSA encryption and decryption, ECDH key
  generation and Z generation, two phase Z generation, ECC encryption and
  decryption, key encapsulation over ECC, curve parameters
- clause 15 symmetric primitives: hashing, HMAC, encryption and decryption
- clause 16 randomness
- clause 17 hash, HMAC and event sequences
- clause 18 attestation and clause 21 auditing
- clause 19 commitment and ephemeral EC points, clause 20 signing and
  verification including the one shot and sequence forms added in version 185
- clause 22 integrity collection
- clause 24 hierarchy administration, clause 25 dictionary attack functions,
  clause 26 miscellaneous management
- clause 28 context management and persistent objects
- clause 30 capabilities, clause 31 NV storage, clause 36 the clock
- the vendor test command

A Primary Object is derived from its hierarchy seed and its template, so the
same TPM2_CreatePrimary always rebuilds the same key, and changing the seed
with TPM2_Clear, TPM2_ChangePPS or TPM2_ChangeEPS makes every object under
that hierarchy unloadable.

## Commands that report a limitation

- TPM2_CertifyX509 answers TPM_RC_COMMAND_CODE: completing a partial X.509
  certificate needs DER encoding that is not implemented.
- TPM2_ACT_SetTimeout, TPM2_AC_Send and TPM2_SetCapability answer
  TPM_RC_VALUE because this TPM has no authenticated timers, no attached
  components and no settable capability.
- TPM2_FieldUpgradeStart and TPM2_FieldUpgradeData answer TPM_RC_COMMAND_CODE
  and TPM_RC_UPGRADE because the firmware is not field upgradeable.
- TPM2_Encapsulate and TPM2_Decapsulate work over ECC. The ML-KEM form is
  refused with TPM_RC_TYPE, as ML-KEM is not implemented.
- TPM2_Commit returns a commitment but keeps no commitment table, so the
  counter it returns is always zero.

## Platform profile

The PCR locality and attribute matrix follows the PC Client Platform Profile
clause 4.7.1 Table 14. PCR 0 through 15 hold the static root of trust and no
command resets them. PCR 16 is the debug register and PCR 23 the application
register. PCR 17 through 20 belong to the dynamic root of trust and are reset
by a D-RTM event rather than by command. PCR 21 and 22 are the TCB registers,
which localities two and three reset. The debug, TCB and application registers
do not advance the PCR update counter.

No PCR of this profile is under policy or authorization value control, so
TPM2_PCR_SetAuthPolicy and TPM2_PCR_SetAuthValue report TPM_RC_VALUE.

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
