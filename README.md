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
  -c, --console                  Run the debug console on stdin
      --ptp                      Follow the PC Client Platform TPM Profile 1.07
                                 as written, which takes SHA-1 away
```

### Platform profile

Without `--ptp` the TPM implements everything the Library Specification
defines, which is what shipping PC Client TPMs do and what callers expect. With
`--ptp` it implements only what the PC Client Platform TPM Profile 1.07 allows.
The two differ in one algorithm, SHA-1; the reasoning is under Algorithms
below. The choice is fixed when the daemon starts and cannot change while it
runs, because a TPM whose algorithm set moved underneath a caller would
invalidate keys and PCR banks already in use.

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

The header carries a version. A file an older build wrote is read with that
build's layout, so a state file survives an upgrade; a file this build cannot
place is refused rather than reinterpreted. A file written before the TPM
recorded which startup method it last used cannot answer what
TPM2_Startup(TPM_SU_STATE) has to compare against, so the first startup after
such an upgrade has to be TPM_SU_CLEAR.

### Software integrity

FIPS 140-3 clause 10.3.1 has a module decide for itself whether its code is the
code it was built as, by comparing it against a value the module holds. A cargo
build has no step that can write such a value into the executable after linking,
so packaging runs the executable once with `--record-integrity`, which writes it
to `<state-dir>/integrity.hex`:

    swtrust --record-integrity --state ./state

Every later start compares the running image against that file. A value that
differs is a failed test and the daemon stops. No file at all means the test
could not be performed, and clause 10.1.1.1 requires it to pass "prior to the
module providing any data output via the data output interface", so the daemon
refuses to serve a transport until one is recorded.

### Logs

Every command and response pair is appended to `<log-dir>/YYYY-MM-DD.log`,
named by the UTC date, with the header decoded and the full buffer in hex.
With `--verbose` the same records also go to stdout.

### Debug console

`--console` runs a console on stdin alongside the transport. It reads and
writes the state the command interface does not report: the PCR banks, the
NV indexes, the working state of the random number generator, and the
public and private halves of loaded and persistent keys.

```
> pcr read 0
0000000000000000000000000000000000000000000000000000000000000000
> pcr extend 0 abababababababababababababababababababababababababababababababab
0 now debb3e7acfff6dd18d501042273629f0b79cb206bb8c24f59f62ddb80849403b
> rng show
key            14e4e589cf40977f013c9878a4f89751f91e49eb27c2812d9628652bfb6fefa7
value          68af31597b0915d5a02b3dd56bcb152c68d40bfa22cbdfb65d36daca1695cb0f
reseed counter 9
needs reseed   false
```

`help` lists every console command. Nothing the console does is a TPM
command: it checks no authorization, records no audit, and can put the TPM
in a state no sequence of commands could reach. It is a debugging aid, and
it is off unless asked for.

### FIPS self tests

The TCG FIPS 140-2 guidance for TPM 2.0, clause 13, and the FIPS 140-3
guidance, clause 10, ask for three kinds of test. All three are in
`src/tpm/fips.rs`.

A pre-operational software integrity test runs at power on, before any
command is accepted. Known answer tests cover every hash the profile in
force implements, so SHA-1 is tested when it is present and is neither
tested nor reported as tested when it is not. They also cover HMAC,
AES in CFB mode both ways, KDFa, KDFe, the DRBG across instantiate, generate
and reseed, ECDH, ECDSA and RSA. A pair-wise consistency test runs on every
key pair the TPM generates, inside TPM2_Create and TPM2_CreatePrimary.

`TPM2_SelfTest(fullTest = YES)` repeats the whole set, which is the periodic
test both standards ask for. A failure puts the TPM in failure mode, where it
produces no further cryptographic output, and `TPM2_GetTestResult` names the
test that failed. The repetition count and adaptive proportion tests of
SP800-90B are applied to the seed material taken from the platform, which is
the continuous test FIPS 140-2 asks for.

Every known answer vector was produced by an implementation other than this
one, and the ones with published values are those values: the digests of
"abc" from FIPS 180-4, RFC 4231 test case 2 for HMAC, and the first CFB128
block of NIST SP800-38A section F.3.13.

What a software TPM cannot assert is written down in the module
documentation rather than glossed over. The integrity test hashes the
executable it was started from, so it detects a corrupted build but not a
process whose memory changed after loading, and the expected value cannot be
held anywhere the host cannot reach. The entropy source belongs to the
platform, so its rate cannot be established here. Keys live in ordinary
process memory, so zeroisation and physical security are out of scope.

## Layout

```
src/
  cli.rs                 command line parsing
  console.rs             the debug console
  logging.rs             the daily command log
  server/                transports: simulator protocol, TCP, named pipe
  tpm/
    fips.rs              FIPS 140-2 and 140-3 self tests
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
  ptp.rs                 the platform profile as written, under --ptp
  legacy.rs              the default profile, which keeps SHA-1
```

## Implemented commands

Every command in the table is dispatched and carries out its operation.

The table is also what TPM2_GetCapability(TPM_CAP_COMMANDS) is built from,
which Part 3 defines as the attributes of "all of the commands implemented in
the TPM". A command that is not implemented is therefore absent from it, and
a caller that sends one is answered TPM_RC_COMMAND_CODE, which is what that
response code means. Part 1 clause 5 allows a command Part 3 does not make
mandatory to be left out; it does not allow one to be left out and still
reported as present.

Four optional commands are left out on that basis:

- TPM2_CertifyX509, because completing and re-encoding a partial X.509
  certificate needs DER handling that is not written.
- TPM2_FieldUpgradeStart, TPM2_FieldUpgradeData and TPM2_FirmwareRead,
  because a software TPM has no field upgradeable firmware to replace or to
  read back.

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

## What the state file does not protect

Part 1 clause 34.7.2.1 requires TPM state held outside the TPM to be encrypted,
integrity checked and rollback protected. This TPM keeps its state as a hex
text file, which is the interface it was asked for, and that file has none of
those protections: a host that can read it can read the hierarchy seeds, the
proofs and the authorization values, and a host that can write it can replace
them or put back an older copy.

That is inherent to a software TPM without a hardware root of trust. The
protections the clause asks for need a key the host cannot reach, and there is
nowhere on the host to keep one that the host cannot also read. A TPM whose
state can be edited by whoever runs it is a development and test instrument,
not a substitute for a discrete TPM, and it is used here for what a discrete
TPM is exercised by: firmware, BitLocker, and the tools that talk to a TPM.

## Commands that report a limitation

- TPM2_ACT_SetTimeout, TPM2_AC_Send and TPM2_SetCapability answer
  TPM_RC_VALUE because this TPM has no authenticated timers, no attached
  components and no settable capability. They are implemented and reported as
  implemented: they check their arguments and refuse a request they cannot
  carry out, rather than denying that the command exists.
- TPM2_Encapsulate and TPM2_Decapsulate work over ECC. The ML-KEM form is
  refused with TPM_RC_TYPE, as ML-KEM is not implemented.

### Split ECC operations

TPM2_Commit, TPM2_EC_Ephemeral, ECDAA signing and TPM2_ZGen_2Phase are the two
command operations of Part 1 clause 44.2. The first command produces a commit
value and returns points derived from it with a counter; the second names that
counter and gets the same value back.

The value is not stored. Clause 44.2.2 derives it by Equation 60 from a nonce,
a counter and the Name of the key, so what is kept is the nonce, the counter
and a bit array of outstanding counters. Clause 44.2.5 bounds which counters a
caller may still name, which is what keeps a value to one use: two ECDAA
signatures over one commit value would give up the private key. Part 1 Table 41
puts all three in the state reset data, so they are written on
Shutdown(STATE), restored by the next Startup, and replaced only by a TPM
Reset.

TPM_PT_SPLIT_MAX reports how many split operations may be outstanding at once.

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
Asymmetric: RSA 2048, 3072 and 4096 with RSASSA, RSAPSS, RSAES and OAEP; ECC on
NIST P-224, P-256, P-384 and P-521 with ECDSA, ECDH, ECDAA and EC Schnorr.

SHA-1 is where the two profiles part. Clause 4.3 Table 3 lists TPM_ALG_SHA1 as
Not Allowed and item 5 of that clause says such an algorithm "SHALL NOT be
supported", but software that runs on real TPMs has not followed. BitLocker
seals its volume master key in an object whose nameAlg is TPM_ALG_SHA1, and the
key a TPM virtual smart card certifies itself with is signed with RSASSA over
SHA-1. Both were seen to fail against a TPM without it.

So both readings are offered. Started with no flag, the TPM keeps SHA-1, which
is what every shipping PC Client TPM does. Started with `--ptp`, it does not
implement SHA-1 at all: the algorithm is not reported, no structure may name
it, and no digest, HMAC or signature can be computed over it. Either way SHA-1
is never among the PCR banks allocated by default, which clause 4.7 item 3
fixes as SHA-256 and SHA-384.

The two are measured separately: `tests/ptp.rs` runs under `--ptp` and checks
the profile as written, `tests/legacy.rs` runs under the default and checks
that the algorithms callers depend on are there.

NIST P-192 is not offered because the underlying library does not build that
group. SM2, SM3, SM4, Camellia, TDES, ML-KEM and ML-DSA are not implemented.
The algorithm set the TPM reports through
TPM2_GetCapability(TPM_CAP_ALGS) matches what it actually implements.

## Tests

```
cargo test
cargo test --release
```

Both profiles are worth running. The debug profile has overflow checks on and
the release profile does not, so an arithmetic mistake shows in only one of
them.

The unit tests check structures against the Part 2 tables and the cryptography
against published vectors: FIPS 180-4 and FIPS 202 for the hashes, RFC 2202 and
RFC 4231 for HMAC, FIPS 197 and SP800-38A for AES, and the standard curve
parameters for ECC. The integration tests drive the TPM through real command
buffers over its own interface, including the split ECC operations end to end
and a commit that has to survive being rebuilt from the state file.

Two tests read the sources themselves rather than running them: one requires
every command to check the end of its parameter area before it changes
anything, and one requires every ECC key pair to be generated through the one
function that runs the pair-wise consistency test.

The socket tests take a free port and then bind it, so an unrelated process
taking that port in between can make them fail. Rerun them if that happens.
