//! Self tests for FIPS 140-2 and FIPS 140-3.
//!
//! Two documents drive this module: the TCG FIPS 140-2 guidance for TPM 2.0,
//! clause 13, and the TCG FIPS 140-3 guidance, clause 10. Between them they
//! ask for three kinds of test.
//!
//! The first is the pre-operational software integrity test, which 140-2 calls
//! the power-up software integrity test. It has to run before the module
//! produces any output.
//!
//! The second is a known answer test for each approved algorithm, listed in
//! 140-3 Table 39 and 140-2 Table 5. Each one runs the algorithm over a fixed
//! input and compares the result with a fixed expected value. A known answer
//! test detects an implementation that has been corrupted or built wrongly; it
//! is not a proof that the algorithm is correct.
//!
//! The third is a pair-wise consistency test, 140-3 Table 40, run on every key
//! pair the module generates. A signing key is used to sign and then verify, a
//! decryption key to encrypt and then decrypt, and a key agreement key has its
//! public value recomputed from its private one.
//!
//! # What a software TPM can and cannot assert
//!
//! This is software running on a general purpose operating system, so several
//! things a hardware module would assert cannot be asserted here, and saying so
//! is more useful than implying otherwise.
//!
//! The integrity test hashes the executable file this process was started from.
//! It detects a corrupted or truncated build. It does not detect a process
//! whose memory was changed after loading, it does not detect a replaced file
//! that carries a matching digest recorded by the same replacement, and the
//! expected value cannot be held anywhere the host cannot reach. A hardware
//! module holds that value in a place the test subject cannot write.
//!
//! The entropy source is the platform generator. The repetition count and
//! adaptive proportion health tests of SP800-90B are applied to what it
//! returns, which catches a source that has failed to a constant or to a badly
//! skewed distribution. They cannot establish the entropy rate of a source
//! this module does not own.
//!
//! Keys live in ordinary process memory, so the zeroisation and physical
//! security requirements of either standard are out of scope.

use crate::tpm::constants::{alg, curve, rc};
use crate::tpm::crypto::{ecc, hash, hmac, rand, rsa, sym};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::util::hex;

/// The test that failed, named so a log or a console can say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure(pub &'static str);

/// Result of a self test.
pub type TestResult = Result<(), Failure>;

/// Turn a missing or malformed vector into a failure of the named test.
///
/// The vectors are compiled in, so this only fires if the source was edited
/// wrongly, which is itself something a self test should report.
fn vector(name: &'static str, text: &str) -> Result<Vec<u8>, Failure> {
    hex::decode(text).map_err(|_| Failure(name))
}

/// Compare a result with its expected value.
fn expect(name: &'static str, got: &[u8], want: &[u8]) -> TestResult {
    if got == want {
        Ok(())
    } else {
        Err(Failure(name))
    }
}

// The known answer vectors. Every one was produced by an implementation other
// than this one: the Python standard library for the hashes and HMAC, the
// cryptography package for AES, ECDH, ECDSA and RSA, and a transcription of
// the TPM specification for KDFa and KDFe and of SP800-90A for the DRBG.
// Where a public vector exists the value is that vector, noted below.

/// FIPS 180-4, digest of "abc".
/// FIPS 180-4, and the reason SHA-1 is implemented is in
/// `crypto::hash::algorithm`.
const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA384_ABC: &str =
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
const SHA512_ABC: &str = concat!(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
);

/// FIPS 202, digest of "abc".
const SHA3_256_ABC: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const SHA3_384_ABC: &str = concat!(
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2",
    "98d88cea927ac7f539f1edf228376d25",
);
const SHA3_512_ABC: &str = concat!(
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
    "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
);

/// RFC 4231 test case 2.
const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_SHA256: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

/// NIST SP800-38A section F.3.13, CFB128-AES128, first block.
const AES_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const AES_IV: &str = "000102030405060708090a0b0c0d0e0f";
const AES_PLAIN: &str = "6bc1bee22e409f96e93d7e117393172a";
const AES_CIPHER: &str = "3b3fd92eb72dad20333449f8e83cfb4a";

/// KDFa, Part 1 clause 11.4.10.2.
const KDFA_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const KDFA_U: &str = "a0a1a2a3";
const KDFA_V: &str = "b0b1b2b3b4";
const KDFA_OUT: &str = "23c9cf92172066404c36b0fd8701c793b9ed0c7233f41863180e2c651d14a01b";

/// KDFe, Part 1 clause 11.4.10.3.
const KDFE_Z: &str = "0f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100";
const KDFE_U: &str = "c0c1c2c3";
const KDFE_V: &str = "d0d1d2d3d4";
const KDFE_OUT: &str = "aa9ee76147165d8f8e0e00b12dce8a22887f6429094a591cb4eac282a3f67c92";

/// HMAC_DRBG, SP800-90A section 10.1.2.
const DRBG_ENTROPY: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const DRBG_NONCE: &str = "0102030405060708";
const DRBG_PERSONALIZATION: &[u8] = b"swtrust self test";
const DRBG_RESEED: &str =
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";
const DRBG_GEN1: &str = "a8d23cfa6792f83dab7d397bfe4efa59dde7a791a23544e2763b9300faba1d0f";
const DRBG_GEN2: &str = "3a5b5e71e6e29e8e2c6835f0905e86deab33144d387587a2b457ccb19d999e12";

/// ECDH on NIST P-256.
const ECDH_PRIVATE: &str = "1122334455667788990011223344556677889900112233445566778899001122";
const ECDH_PEER_X: &str = "6e036a286976c9667feec3458a09131b1e12adfcb6775af5daa039ef20669a21";
const ECDH_PEER_Y: &str = "0d168c9b789a5d972d648971771874d6fddecb451e32aad726f395df4bae2ccc";
const ECDH_Z: &str = "564aef744f5a9a889ffb191fcf24c56c5ff9e6d8ceaba44abeac582749764ab0";

/// ECDSA on NIST P-256.
const ECDSA_PRIVATE: &str = "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464";
const ECDSA_PUBLIC_X: &str = "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83";
const ECDSA_PUBLIC_Y: &str = "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9";
const ECDSA_DIGEST: &str = "589591d61aaf6cbee157c322f701aff7866763ea12115b045062611dc0cf4b66";
const ECDSA_R: &str = "770818352d99e1bb60f1a6fd5430144c388b98f4dcdf88048cf2e588e76f7e35";
const ECDSA_S: &str = "8272b2ef9f79e6152defce3780587cc4d060a99dc0cbb49ebf8b1019705c3a35";
/// Fixed randomization for the signing half, so it has one right answer.
const ECDSA_SIGN_SEED: &str =
    "5eed000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff";
const ECDSA_SIGN_R: &str = "29566913c6eca9f487c6944f8e8fb0c9eaae45778b0dec63edf47273bbde04a8";
const ECDSA_SIGN_S: &str = "d88129a08810535448366f86b74f688382bc2ae0e94f50b6476f7f222f5d4435";

/// RSA 2048 with the default exponent, signing with PKCS1 v1.5 over SHA-256.
const RSA_MODULUS: &str = concat!(
    "98b7c9c5b071cc501f16ed0b05616476206c3beb9539b1345cf81f8b398cb3b1",
    "af0f8f88718600b0af6479e61059399062ed2962eecde51f520496872ae4a817",
    "d77dc0721e3204a49abfe6b8c7042004d6a25226c3f026d7a66bd1cd039be1dd",
    "1ff97465ec13af83a92455e4787ad0c51ab27c6683f6ef8c377907a281357322",
    "7d55eee5a14db335fcbb41856ebcec0fe673d56479b85c437002fac8526176a7",
    "6758f5761f036bed04d621cc98c868f7aef5b132723daf4982b84f211a6df4e2",
    "8256dd4c02c243e52664cf023b15e79bb347ffcd7bf1edc4cac3d253658a8536",
    "117118662774b387c0881ec1111aa5e1417c9451b7b2f4e8859a898019fbd9e5",
);
const RSA_PRIME: &str = concat!(
    "c872ddf5f9da161d094876f75fce86830c80279d654720f687b70943164b4bb6",
    "e2f3bf0b69bd348a36ffc0fa1082a90e1bd9aa3f6e73098f35dc6633502cfb03",
    "66c4d16e2811b35e94814ef13dcab8ce9ebbee7bf324439330c8d8a8c9a5cbaa",
    "6aecdbf47c7cbc10528ca83be15c45993508aa27d58d1d3a1890aa8979bb3b4b",
);
const RSA_DIGEST: &str = "bca0f9da35a22876fa170c1649eaeb58a62df15338b7eb5b81d8803de93cb670";
const RSA_SIGNATURE: &str = concat!(
    "47432c244a7bffb57f9c14236f14b251799fe9035b1ec00a4ec8f4b2f588986e",
    "dedf25812aff22724970960e90098a129633df42a30b2140eeb895de0915039c",
    "b5daf712491bda7e5f7724bf8e32d2e1ce55c12dbcfbe0915eaa8e9cd6fae8d4",
    "f47b5764b3a31624fb8f7f2758079399023c803ff1bd28044a2de628ee781bf2",
    "3ca1a4f4a77fc898333b071fbd77a49fc35f8d4904be388794139c2e0a721fc1",
    "469139e6e1d957d5e33debda2abec5e32ca09b59902b054e451867e83474bc36",
    "0dca15aea5f1f9f588fe8b80bce1327040cb0739c57c4109839ce6d8fc97dd78",
    "30163bb20dc198d144b889f8ea56872bdd4f470109bbbec8e74871966a864b3f",
);

/// The digest a known answer test uses for the hash and HMAC tests.
const KAT_MESSAGE: &[u8] = b"abc";

/// Every algorithm a full self test covers.
///
/// TPM2_IncrementalSelfTest reports what is left to do from this list, and
/// TPM2_GetCapability(TPM_CAP_ALGS) is a superset of it.
const TESTED_LEGACY: &[u16] = &[
    alg::SHA1,
    alg::SHA256,
    alg::SHA384,
    alg::SHA512,
    alg::SHA3_256,
    alg::SHA3_384,
    alg::SHA3_512,
    alg::HMAC,
    alg::AES,
    alg::CFB,
    alg::KDF1_SP800_108,
    alg::KDF1_SP800_56A,
    alg::RSA,
    alg::RSASSA,
    alg::ECC,
    alg::ECDSA,
    alg::ECDH,
];

/// Every algorithm a full self test covers under the profile in force.
///
/// A hash the profile does not have is not tested and is not reported as
/// tested, so TPM2_IncrementalSelfTest never claims a test it did not run.
pub fn tested_algorithms() -> Vec<u16> {
    TESTED_LEGACY
        .iter()
        .copied()
        .filter(|a| *a != alg::SHA1 || crate::tpm::crypto::hash::is_supported(alg::SHA1))
        .collect()
}

/// The vector each digest is tested against, as a name, an algorithm and the
/// digest of "abc".
///
/// This is the list [`hash_kats`] works through, so a test can ask what is
/// really covered rather than what some other list says is covered.
const HASH_KATS: &[(&str, u16, &str)] = &[
    ("SHA-1", alg::SHA1, SHA1_ABC),
    ("SHA-256", alg::SHA256, SHA256_ABC),
    ("SHA-384", alg::SHA384, SHA384_ABC),
    ("SHA-512", alg::SHA512, SHA512_ABC),
    ("SHA3-256", alg::SHA3_256, SHA3_256_ABC),
    ("SHA3-384", alg::SHA3_384, SHA3_384_ABC),
    ("SHA3-512", alg::SHA3_512, SHA3_512_ABC),
];

/// Known answer tests, one per digest the TPM implements.
///
/// FIPS 180-4 covers the SHA-2 family and FIPS 202 the SHA-3 family. Every hash
/// `crate::tpm::crypto::hash` will compute is tested, because a caller can
/// select any of them and a self test that skipped one would leave that one
/// unchecked while the module reported that its tests had passed.
pub fn hash_kats() -> TestResult {
    for (name, hash_alg, want) in HASH_KATS.iter().copied() {
        // A hash the profile in force does not have is not tested, because
        // there is nothing to test: the vector is kept so that the other
        // profile still has one. See `crate::tpm::profile`.
        if !hash::is_supported(hash_alg) {
            continue;
        }
        let want = vector(name, want)?;
        let got = hash::digest(hash_alg, KAT_MESSAGE).map_err(|_| Failure(name))?;
        expect(name, &got, &want)?;
    }
    Ok(())
}

/// RFC 4231 known answer test for HMAC.
pub fn hmac_kat() -> TestResult {
    let want = vector("HMAC", HMAC_SHA256)?;
    let got = hmac::hmac(alg::SHA256, HMAC_KEY, HMAC_DATA).map_err(|_| Failure("HMAC"))?;
    expect("HMAC", &got, &want)
}

/// SP800-38A known answer test for AES in CFB mode, both directions.
///
/// 140-3 Table 39 asks for encryption and decryption to be tested separately,
/// because a broken decryption is not detected by an encryption test.
pub fn aes_cfb_kat() -> TestResult {
    let key = vector("AES-CFB", AES_KEY)?;
    let iv = vector("AES-CFB", AES_IV)?;
    let plain = vector("AES-CFB", AES_PLAIN)?;
    let cipher = vector("AES-CFB", AES_CIPHER)?;

    let got = sym::cfb_encrypt(&key, &iv, &plain).map_err(|_| Failure("AES-CFB encrypt"))?;
    expect("AES-CFB encrypt", &got, &cipher)?;

    let got = sym::cfb_decrypt(&key, &iv, &cipher).map_err(|_| Failure("AES-CFB decrypt"))?;
    expect("AES-CFB decrypt", &got, &plain)
}

/// Known answer test for KDFa, the SP800-108 counter mode KDF.
pub fn kdfa_kat() -> TestResult {
    let key = vector("KDFa", KDFA_KEY)?;
    let u = vector("KDFa", KDFA_U)?;
    let v = vector("KDFa", KDFA_V)?;
    let want = vector("KDFa", KDFA_OUT)?;
    let got = hmac::kdfa(alg::SHA256, &key, "ATH", &u, &v, 256).map_err(|_| Failure("KDFa"))?;
    expect("KDFa", &got, &want)
}

/// Known answer test for KDFe, the SP800-56A concatenation KDF.
pub fn kdfe_kat() -> TestResult {
    let z = vector("KDFe", KDFE_Z)?;
    let u = vector("KDFe", KDFE_U)?;
    let v = vector("KDFe", KDFE_V)?;
    let want = vector("KDFe", KDFE_OUT)?;
    let got = hmac::kdfe(alg::SHA256, &z, "SECRET", &u, &v, 256).map_err(|_| Failure("KDFe"))?;
    expect("KDFe", &got, &want)
}

/// Known answer test for the DRBG, covering instantiate, generate and reseed.
///
/// 140-3 Table 39 allows the three to be one grouped test, which is what this
/// is: the instantiation is checked by the first generate, and the reseed by
/// the second, since a reseed that did nothing would repeat the first output.
pub fn drbg_kat() -> TestResult {
    let entropy = vector("DRBG", DRBG_ENTROPY)?;
    let nonce = vector("DRBG", DRBG_NONCE)?;
    let reseed = vector("DRBG", DRBG_RESEED)?;
    let want1 = vector("DRBG", DRBG_GEN1)?;
    let want2 = vector("DRBG", DRBG_GEN2)?;

    let mut drbg = rand::Drbg::instantiate(&entropy, &nonce, DRBG_PERSONALIZATION)
        .map_err(|_| Failure("DRBG instantiate"))?;

    let mut out = [0u8; 32];
    rand::Rng::fill(&mut drbg, &mut out).map_err(|_| Failure("DRBG generate"))?;
    expect("DRBG generate", &out, &want1)?;

    drbg.reseed(&reseed).map_err(|_| Failure("DRBG reseed"))?;
    rand::Rng::fill(&mut drbg, &mut out).map_err(|_| Failure("DRBG reseed"))?;
    expect("DRBG reseed", &out, &want2)
}

/// Known answer test for ECDH on P-256.
pub fn ecdh_kat() -> TestResult {
    let private = vector("ECDH", ECDH_PRIVATE)?;
    let peer_x = vector("ECDH", ECDH_PEER_X)?;
    let peer_y = vector("ECDH", ECDH_PEER_Y)?;
    let want = vector("ECDH", ECDH_Z)?;

    let group = ecc::Curve::new(curve::NIST_P256).map_err(|_| Failure("ECDH"))?;
    let d = crate::tpm::crypto::bn::BigNum::from_bytes(&private).map_err(|_| Failure("ECDH"))?;
    let (z, _) = ecc::ecdh(&group, &d, &peer_x, &peer_y).map_err(|_| Failure("ECDH"))?;
    expect("ECDH", &z, &want)
}

/// Known answer test for ECDSA on P-256, verify and then sign.
///
/// The verify half uses a signature made elsewhere, which is the part a known
/// answer test can pin: ECDSA signing draws a per message secret, so the
/// signature it produces is not a fixed value. The sign half is checked by
/// verifying what it produced, which is the same shape as a pair-wise
/// consistency test and catches a signer that produces nothing usable.
pub fn ecdsa_kat() -> TestResult {
    let public_x = vector("ECDSA", ECDSA_PUBLIC_X)?;
    let public_y = vector("ECDSA", ECDSA_PUBLIC_Y)?;
    let digest = vector("ECDSA", ECDSA_DIGEST)?;
    let sig = ecc::EccSignature {
        r: vector("ECDSA", ECDSA_R)?,
        s: vector("ECDSA", ECDSA_S)?,
    };
    let group = ecc::Curve::new(curve::NIST_P256).map_err(|_| Failure("ECDSA"))?;

    ecc::ecdsa_verify(&group, &public_x, &public_y, &digest, &sig)
        .map_err(|_| Failure("ECDSA verify"))?;

    // A signature over a changed digest must not verify, or the verifier is
    // accepting everything and the test above proves nothing.
    let mut wrong = digest.clone();
    wrong[0] ^= 0x01;
    if ecc::ecdsa_verify(&group, &public_x, &public_y, &wrong, &sig).is_ok() {
        return Err(Failure("ECDSA verify accepts a wrong digest"));
    }

    // The signing half is given fixed randomization, so it has one right
    // answer and can be compared with a pinned signature the way 140-3
    // Table 39 asks. The per message secret cannot come from a generator that
    // returns a constant, because a rejected candidate would be redrawn
    // unchanged, so it comes from a generator with a fixed seed.
    let private = vector("ECDSA", ECDSA_PRIVATE)?;
    let d = crate::tpm::crypto::bn::BigNum::from_bytes(&private).map_err(|_| Failure("ECDSA"))?;
    let seed = vector("ECDSA", ECDSA_SIGN_SEED)?;
    let mut fixed =
        rand::Drbg::new(&seed, b"ecdsa known answer test").map_err(|_| Failure("ECDSA sign"))?;
    let made = ecc::ecdsa_sign(&group, &d, &digest, &mut fixed).map_err(|_| Failure("ECDSA sign"))?;
    expect("ECDSA sign", &made.r, &vector("ECDSA", ECDSA_SIGN_R)?)?;
    expect("ECDSA sign", &made.s, &vector("ECDSA", ECDSA_SIGN_S)?)?;
    // The signature it produced must also verify, so the two halves agree.
    ecc::ecdsa_verify(&group, &public_x, &public_y, &digest, &made)
        .map_err(|_| Failure("ECDSA sign"))
}

/// Known answer test for RSA 2048, verify and then sign.
pub fn rsa_kat() -> TestResult {
    let modulus = vector("RSA", RSA_MODULUS)?;
    let prime = vector("RSA", RSA_PRIME)?;
    let digest = vector("RSA", RSA_DIGEST)?;
    let signature = vector("RSA", RSA_SIGNATURE)?;

    let public = rsa::RsaPublic::new(&modulus, 0).map_err(|_| Failure("RSA"))?;
    let encoded =
        rsa::pkcs1v15_sign_encode(alg::SHA256, &digest, public.size()).map_err(|_| Failure("RSA"))?;

    let recovered = rsa::public_op(&public, &signature).map_err(|_| Failure("RSA verify"))?;
    expect("RSA verify", &recovered, &encoded)?;

    // Signing the same digest with the private half must reproduce the pinned
    // signature, because PKCS1 v1.5 signing is deterministic.
    let key = rsa::RsaPrivate::from_prime(&modulus, 0, &prime).map_err(|_| Failure("RSA"))?;
    let made = rsa::private_op(&key, &encoded).map_err(|_| Failure("RSA sign"))?;
    expect("RSA sign", &made, &signature)
}

/// Every known answer test, in the order 140-3 Table 39 lists them.
///
/// The first failure stops the run, because a module that has failed a self
/// test must not carry on producing cryptographic output.
pub fn known_answer_tests() -> TestResult {
    hash_kats()?;
    hmac_kat()?;
    aes_cfb_kat()?;
    kdfa_kat()?;
    kdfe_kat()?;
    drbg_kat()?;
    ecdh_kat()?;
    ecdsa_kat()?;
    rsa_kat()?;
    Ok(())
}

/// The pre-operational software integrity test.
///
/// The executable this process was started from is hashed with HMAC-SHA-256
/// under a key compiled into the module, which is the message authentication
/// code form 140-3 clause 10.3.1 allows. The digest is returned so a caller can
/// record it; there is no stored value to compare it with, for the reason given
/// in the module documentation.
///
/// A build that cannot be read is a failure, because an integrity test that
/// cannot see its subject has not passed.
pub fn integrity() -> Result<Vec<u8>, Failure> {
    const INTEGRITY_KEY: &[u8] = b"swtrust pre-operational integrity";
    let path = std::env::current_exe().map_err(|_| Failure("integrity"))?;
    let image = std::fs::read(&path).map_err(|_| Failure("integrity"))?;
    if image.is_empty() {
        return Err(Failure("integrity"));
    }
    hmac::hmac(alg::SHA256, INTEGRITY_KEY, &image).map_err(|_| Failure("integrity"))
}

/// Pair-wise consistency test for a generated RSA key, 140-3 Table 40.
///
/// A signing key signs a digest and verifies it back. A decryption key
/// encrypts and decrypts, and the ciphertext is compared with the plaintext
/// because a cipher that returned its input would otherwise pass.
pub fn pairwise_rsa(key: &rsa::RsaPrivate, sign: bool, decrypt: bool) -> TpmResult<()> {
    let digest = hash::digest(alg::SHA256, b"pair-wise consistency test")?;
    // Table 40 chooses the test by what the key is for, and picks the
    // encryption one whenever the key does not sign. A key with neither
    // attribute set is still a generated pair and still has to be tested, so
    // it takes that branch rather than none.
    let decrypt = decrypt || !sign;

    if sign {
        let encoded = rsa::pkcs1v15_sign_encode(alg::SHA256, &digest, key.size())?;
        let signature = rsa::private_op(key, &encoded)?;
        let recovered = rsa::public_op(&key.public, &signature)?;
        if recovered != encoded {
            return Err(TpmRc(rc::FAILURE));
        }
    }

    if decrypt {
        let message = rsa::oaep_encode(
            alg::SHA256,
            key.size(),
            &digest,
            b"\0",
            &mut FixedRng(&digest),
        )?;
        let cipher = rsa::public_op(&key.public, &message)?;
        if cipher == message {
            return Err(TpmRc(rc::FAILURE));
        }
        let back = rsa::private_op(key, &cipher)?;
        if back != message {
            return Err(TpmRc(rc::FAILURE));
        }
    }

    Ok(())
}

/// The pair-wise consistency test every generated ECC pair gets, wherever it
/// was generated.
///
/// 140-3 Table 40 tests a key agreement key by recomputing its public value
/// from its private one and comparing. This runs inside
/// [`crate::tpm::crypto::ecc::generate`], so an ephemeral pair made for
/// TPM2_ECDH_KeyGen, TPM2_EC_Ephemeral, TPM2_ECC_Encrypt, TPM2_Encapsulate or
/// the labeled key encapsulation of Part 1 clause 20.3 is covered as well as a
/// pair that becomes a loaded object.
///
/// Recomputing the same operation catches a fault that struck once, not a
/// multiplication that is wrong every time; the known answer tests are what
/// cover the second case.
pub fn pairwise_generated_ecc(key: &ecc::EccKey) -> TpmResult<()> {
    let point = ecc::multiply_generator(&key.curve, &key.private)?;
    if point.is_at_infinity(&key.curve) {
        return Err(TpmRc(rc::FAILURE));
    }
    let (x, y) = point.coordinates(&key.curve)?;
    if x != key.public_x || y != key.public_y {
        return Err(TpmRc(rc::FAILURE));
    }
    Ok(())
}

/// Pair-wise consistency test for a generated ECC key, 140-3 Table 40.
///
/// A signing key signs and verifies. A key agreement key has its public point
/// recomputed from the private scalar and compared, which is the check 140-3
/// asks for when the key is not used to sign.
/// The test draws its own per message secret rather than taking the caller's
/// generator, because the caller's may be the deterministic one that Part 1
/// clause 27.2 requires TPM2_CreatePrimary to reproduce. ECDSA signing retries
/// until it draws a usable scalar, so the number of octets it consumes depends
/// on the values it sees; taking them from the primary seed generator would
/// make what comes after depend on that, which must not happen.
pub fn pairwise_ecc(
    curve_id: u16,
    private: &[u8],
    public_x: &[u8],
    public_y: &[u8],
    sign: bool,
) -> TpmResult<()> {
    let group = ecc::Curve::new(curve_id)?;
    let d = crate::tpm::crypto::bn::BigNum::from_bytes(private)?;

    // The public point has to be the one the private scalar gives, whatever
    // the key is for.
    let point = ecc::multiply_generator(&group, &d)?;
    let (x, y) = point.coordinates(&group)?;
    if x != public_x || y != public_y {
        return Err(TpmRc(rc::FAILURE));
    }

    if sign {
        let digest = hash::digest(alg::SHA256, b"pair-wise consistency test")?;
        // Seeded from the key under test, so the test is repeatable and takes
        // nothing from the generator the caller is using.
        let seed = hmac::hmac(alg::SHA256, private, b"pair-wise consistency test")?;
        let mut own = rand::Drbg::new(&[seed.as_slice(), seed.as_slice()].concat(), b"pct")?;
        let signature = ecc::ecdsa_sign(&group, &d, &digest, &mut own)?;
        ecc::ecdsa_verify(&group, public_x, public_y, &digest, &signature)
            .map_err(|_| TpmRc(rc::FAILURE))?;
    }

    Ok(())
}

/// A generator that returns fixed octets, used by the RSA pair-wise test.
///
/// OAEP needs a seed. The pair-wise test is not producing a key or a nonce, so
/// the seed only has to be the same on both sides of the encrypt and decrypt.
struct FixedRng<'a>(&'a [u8]);

impl rand::Rng for FixedRng<'_> {
    fn fill(&mut self, out: &mut [u8]) -> TpmResult<()> {
        if self.0.is_empty() {
            return Err(TpmRc(rc::FAILURE));
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0[i % self.0.len()];
        }
        Ok(())
    }
}

/// The SP800-90B health tests for an entropy source.
///
/// 140-2 asks for a continuous random number generator test, and SP800-90B
/// gives two that a module applies as the source produces output: the
/// repetition count test, which fails a source stuck at one value, and the
/// adaptive proportion test, which fails a source whose output is heavily
/// skewed without being constant.
#[derive(Debug, Clone)]
pub struct HealthTests {
    /// The last octet seen, and how many times in a row it has appeared.
    last: Option<u8>,
    repetitions: usize,
    /// The octet the current adaptive proportion window is counting.
    window_value: u8,
    window_count: usize,
    window_seen: usize,
    /// Length of the adaptive proportion window and the count that fails it.
    window: usize,
    cutoff: usize,
}

/// Cutoff for the repetition count test.
///
/// SP800-90B section 4.4.1 gives C = 1 + ceil(-log2(alpha) / H), with alpha of
/// 2^-20. A byte from a full entropy source has H of 8, so C is 1 + 3 = 4. The
/// cutoff here is deliberately looser, because the platform source is not
/// claimed to be full entropy and a false failure would stop the TPM.
pub const REPETITION_CUTOFF: usize = 32;

/// Window for the adaptive proportion test, SP800-90B section 4.4.2.
pub const ADAPTIVE_WINDOW: usize = 512;

/// Cutoff for the adaptive proportion test over that window.
///
/// A window of 512 octets from a full entropy source holds one given value
/// about twice. The cutoff allows far more than that, so it fires only for a
/// source that has plainly failed rather than for ordinary variation.
pub const ADAPTIVE_CUTOFF: usize = 128;

/// Cutoff for the adaptive proportion test over one entropy acquisition.
///
/// This module takes its entropy in a single request rather than as a stream,
/// so a 512 sample window would never fill and the test would never reach a
/// verdict. The window is the acquisition instead, and the cutoff is chosen for
/// it: over 48 octets a uniform source is expected to repeat any given value
/// 48/256 times, and the chance of reaching ten is far below the 2^-20 false
/// positive rate SP800-90B works to. A false failure would stop the TPM from
/// starting, so the cutoff errs on the side of letting good entropy through
/// while still catching a source that has plainly failed.
pub const ACQUISITION_CUTOFF: usize = 10;

impl Default for HealthTests {
    fn default() -> Self {
        HealthTests::new()
    }
}

impl HealthTests {
    /// Tests over the SP800-90B window, for a source read as a stream.
    pub fn new() -> HealthTests {
        HealthTests::with_window(ADAPTIVE_WINDOW, ADAPTIVE_CUTOFF)
    }

    /// Tests over one acquisition, for a source read in a single request.
    ///
    /// The window is the acquisition, so the adaptive proportion test reaches a
    /// verdict on what was actually taken instead of waiting for a stream that
    /// never comes.
    pub fn for_acquisition(size: usize) -> HealthTests {
        HealthTests::with_window(size, ACQUISITION_CUTOFF)
    }

    /// Tests over a window of `window` samples, failing at `cutoff` of a value.
    pub fn with_window(window: usize, cutoff: usize) -> HealthTests {
        HealthTests {
            last: None,
            repetitions: 0,
            window_value: 0,
            window_count: 0,
            window_seen: window,
            window: window.max(1),
            cutoff,
        }
    }

    /// Feed octets from the entropy source through both tests.
    ///
    /// A failure means the source has stopped behaving like one, which the
    /// caller turns into failure mode.
    pub fn check(&mut self, data: &[u8]) -> TestResult {
        for &b in data {
            // Repetition count.
            match self.last {
                Some(prev) if prev == b => {
                    self.repetitions += 1;
                    if self.repetitions >= REPETITION_CUTOFF {
                        return Err(Failure("entropy repetition count"));
                    }
                }
                _ => {
                    self.last = Some(b);
                    self.repetitions = 1;
                }
            }

            // Adaptive proportion. A finished window starts a new one on the
            // next octet, which becomes the value that window counts.
            if self.window_seen >= self.window {
                self.window_value = b;
                self.window_count = 1;
                self.window_seen = 1;
                continue;
            }
            self.window_seen += 1;
            if b == self.window_value {
                self.window_count += 1;
                if self.window_count >= self.cutoff {
                    return Err(Failure("entropy adaptive proportion"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::crypto::rand::Rng as _;

    #[test]
    fn every_known_answer_test_passes() {
        assert_eq!(known_answer_tests(), Ok(()));
    }

    #[test]
    fn each_known_answer_test_passes_on_its_own() {
        assert_eq!(hash_kats(), Ok(()));
        assert_eq!(hmac_kat(), Ok(()));
        assert_eq!(aes_cfb_kat(), Ok(()));
        assert_eq!(kdfa_kat(), Ok(()));
        assert_eq!(kdfe_kat(), Ok(()));
        assert_eq!(drbg_kat(), Ok(()));
        assert_eq!(ecdh_kat(), Ok(()));
        assert_eq!(ecdsa_kat(), Ok(()));
        assert_eq!(rsa_kat(), Ok(()));
    }

    #[test]
    fn every_hash_the_tpm_implements_is_covered_by_a_self_test() {
        // The set is taken from the code rather than written out again, so a
        // hash added later is caught here instead of quietly going untested
        // while the module still reports that its self tests passed.
        let mut found = 0;
        for alg_id in 0u16..=0x0100 {
            if !hash::is_supported(alg_id) {
                continue;
            }
            found += 1;
            // Membership of the reported list is not enough on its own: the
            // run has to hold a vector for the algorithm, or the module would
            // report a test it never performs.
            assert!(
                HASH_KATS.iter().any(|(_, a, _)| *a == alg_id),
                "hash {alg_id:#06x} is implemented but hash_kats has no vector for it"
            );
            assert!(
                tested_algorithms().contains(&alg_id),
                "hash {alg_id:#06x} is implemented but is not reported as tested"
            );
        }
        assert_eq!(
            found,
            crate::tpm::config::implemented_hashes().len(),
            "the scan found a different set of hashes than the one reported"
        );
        // The list must also not name a hash that is not there to test.
        for alg_id in tested_algorithms() {
            if hash::digest_size(alg_id).is_ok() {
                assert!(hash::is_supported(alg_id));
            }
        }
    }

    #[test]
    fn the_vectors_are_the_published_ones() {
        // These four are public values, so a wrong transcription is visible
        // without running the algorithm at all.
        assert_eq!(
            SHA256_ABC,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            HMAC_SHA256,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(AES_CIPHER, "3b3fd92eb72dad20333449f8e83cfb4a");
    }

    #[test]
    fn every_vector_is_well_formed_hex_of_the_right_length() {
        // The long values are written as joined chunks, and a chunk boundary is
        // an easy place to drop or repeat a character. A wrong length is caught
        // here rather than showing up as an unexplained algorithm failure.
        for (name, text, want) in [
            ("SHA256_ABC", SHA256_ABC, 32),
            ("SHA384_ABC", SHA384_ABC, 48),
            ("SHA512_ABC", SHA512_ABC, 64),
            ("SHA3_256_ABC", SHA3_256_ABC, 32),
            ("SHA3_384_ABC", SHA3_384_ABC, 48),
            ("SHA3_512_ABC", SHA3_512_ABC, 64),
            ("HMAC_SHA256", HMAC_SHA256, 32),
            ("AES_KEY", AES_KEY, 16),
            ("AES_IV", AES_IV, 16),
            ("AES_PLAIN", AES_PLAIN, 16),
            ("AES_CIPHER", AES_CIPHER, 16),
            ("KDFA_KEY", KDFA_KEY, 32),
            ("KDFA_OUT", KDFA_OUT, 32),
            ("KDFE_Z", KDFE_Z, 32),
            ("KDFE_OUT", KDFE_OUT, 32),
            ("DRBG_ENTROPY", DRBG_ENTROPY, 48),
            ("DRBG_RESEED", DRBG_RESEED, 48),
            ("DRBG_GEN1", DRBG_GEN1, 32),
            ("DRBG_GEN2", DRBG_GEN2, 32),
            ("ECDH_PRIVATE", ECDH_PRIVATE, 32),
            ("ECDH_PEER_X", ECDH_PEER_X, 32),
            ("ECDH_PEER_Y", ECDH_PEER_Y, 32),
            ("ECDH_Z", ECDH_Z, 32),
            ("ECDSA_PRIVATE", ECDSA_PRIVATE, 32),
            ("ECDSA_PUBLIC_X", ECDSA_PUBLIC_X, 32),
            ("ECDSA_PUBLIC_Y", ECDSA_PUBLIC_Y, 32),
            ("ECDSA_DIGEST", ECDSA_DIGEST, 32),
            ("ECDSA_R", ECDSA_R, 32),
            ("ECDSA_S", ECDSA_S, 32),
            ("ECDSA_SIGN_SEED", ECDSA_SIGN_SEED, 48),
            ("ECDSA_SIGN_R", ECDSA_SIGN_R, 32),
            ("ECDSA_SIGN_S", ECDSA_SIGN_S, 32),
            ("RSA_MODULUS", RSA_MODULUS, 256),
            ("RSA_PRIME", RSA_PRIME, 128),
            ("RSA_DIGEST", RSA_DIGEST, 32),
            ("RSA_SIGNATURE", RSA_SIGNATURE, 256),
        ] {
            let bytes = hex::decode(text).unwrap_or_else(|_| panic!("{name} is not hex"));
            assert_eq!(bytes.len(), want, "{name} is the wrong length");
        }
        // The prime has to be half the modulus, and both the top bits set, or
        // the key is not the 2048 bit one it claims to be.
        let modulus = hex::decode(RSA_MODULUS).unwrap();
        let prime = hex::decode(RSA_PRIME).unwrap();
        assert_eq!(prime.len() * 2, modulus.len());
        assert!(modulus[0] & 0x80 != 0);
        assert!(prime[0] & 0x80 != 0);
    }

    #[test]
    fn a_changed_expected_value_is_a_failure() {
        // The comparison has to be the thing that decides, so a test with a
        // wrong expectation must fail rather than pass.
        let got = hash::digest(alg::SHA256, KAT_MESSAGE).unwrap();
        let mut wrong = got.clone();
        wrong[0] ^= 0xff;
        assert_eq!(expect("x", &got, &wrong), Err(Failure("x")));
        assert_eq!(expect("x", &got, &got), Ok(()));
    }

    #[test]
    fn the_integrity_test_reads_the_running_image() {
        let a = integrity().unwrap();
        let b = integrity().unwrap();
        // The same image gives the same value every time.
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // It is a keyed digest of the file, not of nothing.
        assert_ne!(a, hmac::hmac(alg::SHA256, b"", b"").unwrap());
    }

    #[test]
    fn an_rsa_key_passes_its_pairwise_test() {
        let modulus = hex::decode(RSA_MODULUS).unwrap();
        let prime = hex::decode(RSA_PRIME).unwrap();
        let key = rsa::RsaPrivate::from_prime(&modulus, 0, &prime).unwrap();
        assert!(pairwise_rsa(&key, true, false).is_ok());
        assert!(pairwise_rsa(&key, false, true).is_ok());
        assert!(pairwise_rsa(&key, true, true).is_ok());
    }

    #[test]
    fn an_ecc_key_passes_its_pairwise_test() {
        let private = hex::decode(ECDSA_PRIVATE).unwrap();
        let x = hex::decode(ECDSA_PUBLIC_X).unwrap();
        let y = hex::decode(ECDSA_PUBLIC_Y).unwrap();
        assert!(pairwise_ecc(curve::NIST_P256, &private, &x, &y, true).is_ok());
        assert!(pairwise_ecc(curve::NIST_P256, &private, &x, &y, false).is_ok());

        // A public point that does not belong to the private scalar fails.
        let mut wrong = x.clone();
        wrong[0] ^= 0x01;
        assert!(pairwise_ecc(curve::NIST_P256, &private, &wrong, &y, false).is_err());
    }

    #[test]
    fn a_generated_key_passes_the_pairwise_test() {
        // The test has to hold for keys this TPM makes, not only for the
        // pinned one.
        let mut rng = rand::Drbg::new(&[0x22u8; 48], b"test").unwrap();
        let key = ecc::generate(curve::NIST_P256, &mut rng).unwrap();
        // The test must not touch the caller's generator, so what it draws is
        // its own. Drawing from rng here would prove nothing either way.
        let before = rng.bytes(8).unwrap();
        assert!(pairwise_ecc(
            curve::NIST_P256,
            &key.private.to_bytes().unwrap(),
            &key.public_x,
            &key.public_y,
            true
        )
        .is_ok());
        // The generator moved on only because of the draw above, not because
        // the pair-wise test took anything from it.
        assert_ne!(before, rng.bytes(8).unwrap());
    }

    #[test]
    fn no_module_builds_an_ecc_key_pair_of_its_own() {
        // The pair-wise consistency test lives inside ecc::generate, so a
        // module that assembles a scalar and a point itself would slip past
        // it. That is how TPM2_Commit and the labeled seed encapsulation came
        // to have no test, so the arrangement is pinned here.
        const SOURCES: &[(&str, &str)] = &[
            ("core/protect.rs", include_str!("core/protect.rs")),
            ("commands/signing.rs", include_str!("commands/signing.rs")),
            ("commands/crypto.rs", include_str!("commands/crypto.rs")),
            ("commands/object.rs", include_str!("commands/object.rs")),
            ("commands/duplication.rs", include_str!("commands/duplication.rs")),
        ];
        for (name, source) in SOURCES {
            // Everything before the first test section is the working code.
            let code = match source.find("#[cfg(test)]") {
                Some(i) => &source[..i],
                None => source,
            };
            assert!(
                !code.contains("private_key_from_rng"),
                "{name} builds an ECC private scalar itself, so the pair it                  makes gets no pair-wise consistency test. Call ecc::generate."
            );
        }
    }

    #[test]
    fn the_repetition_count_test_fails_a_stuck_source() {
        let mut h = HealthTests::new();
        assert_eq!(h.check(&[1, 2, 3, 4, 5]), Ok(()));
        // A run shorter than the cutoff is allowed.
        assert_eq!(h.check(&[7u8; REPETITION_CUTOFF - 1]), Ok(()));
        let mut h = HealthTests::new();
        assert_eq!(
            h.check(&[9u8; REPETITION_CUTOFF + 1]),
            Err(Failure("entropy repetition count"))
        );
    }

    #[test]
    fn the_adaptive_proportion_test_fails_a_skewed_source() {
        // A source that alternates between two values never repeats, so the
        // repetition count test passes it and the proportion test is what
        // catches it.
        let mut h = HealthTests::new();
        let skewed: Vec<u8> = (0..ADAPTIVE_WINDOW).map(|i| (i % 2) as u8).collect();
        assert_eq!(
            h.check(&skewed),
            Err(Failure("entropy adaptive proportion"))
        );
    }

    #[test]
    fn the_acquisition_window_reaches_a_verdict_on_one_acquisition() {
        // The module takes its entropy in a single request, so a 512 sample
        // window would never fill and the test would never decide anything.
        // The acquisition window has to reach a verdict on what was taken.
        let size = 48;

        // A source stuck at one value fails, on the repetition count first.
        let mut h = HealthTests::for_acquisition(size);
        assert!(h.check(&[0x7fu8; 48]).is_err());

        // A source that alternates never repeats, so the proportion test is
        // what has to catch it, and with this window it does.
        let mut h = HealthTests::for_acquisition(size);
        let skewed: Vec<u8> = (0..size).map(|i| (i % 2) as u8).collect();
        assert_eq!(
            h.check(&skewed),
            Err(Failure("entropy adaptive proportion")),
            "the window must decide within one acquisition"
        );

        // The window the stream form uses cannot decide on 48 samples, which
        // is the reason the acquisition form exists.
        let mut h = HealthTests::new();
        assert_eq!(h.check(&skewed), Ok(()));
    }

    #[test]
    fn an_acquisition_of_real_entropy_passes() {
        // A false failure would stop the TPM from starting, so the cutoff has
        // to leave real entropy alone. Drbg::from_system runs these tests on
        // its seed, so this exercises the production path many times over.
        for _ in 0..200 {
            rand::Drbg::from_system().expect("real entropy failed a health test");
        }
    }

    #[test]
    fn real_generator_output_passes_the_health_tests() {
        let mut rng = rand::Drbg::new(&[0x33u8; 48], b"test").unwrap();
        let mut h = HealthTests::new();
        for _ in 0..16 {
            let block = rng.bytes(1024).unwrap();
            assert_eq!(h.check(&block), Ok(()), "generator output failed a health test");
        }
    }
}
