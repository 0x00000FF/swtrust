//! TPM2_CertifyX509, Part 3 clause 18.8.
//!
//! The caller hands in a DER encoded partial certificate holding the fields
//! only it can know, and the TPM adds the fields only it can know: the version,
//! a serial number, the public key of the object being certified and, when the
//! caller left it out, the signature algorithm identifier. The two together are
//! an RFC 5280 TBSCertificate, which the TPM hashes and signs.
//!
//! The command was deprecated in revision 184 because, as Part 0 clause 3.1.3.3
//! puts it, "its nuances caused confusion". It is still defined, so it is still
//! here.

use crate::tpm::constants::{alg, curve, rc};
use crate::tpm::core::object::Object;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::hash;
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::structures::attributes::{ObjectAttributes, X509KeyUsage};
use crate::tpm::structures::base::{Tpm2bData, Tpm2bDigest, Tpm2bMaxBuffer};
use crate::tpm::structures::der::{self, tag};
use crate::tpm::structures::keys::{PublicId, PublicParms};
use crate::tpm::structures::schemes::Scheme;
use crate::tpm::marshal::{Marshal, Unmarshal};

use super::dispatch::{Request, Response};
use super::execute::respond;

/// The X.509 KeyUsage extension, RFC 5280 clause 4.2.1.3: 2.5.29.15.
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// tcg-tpmaObject, 2.23.133.10.1.1.1, which Part 3 clause 18.8.1 names.
const OID_TPMA_OBJECT: &[u8] = &[0x67, 0x81, 0x05, 0x0A, 0x01, 0x01, 0x01];
/// rsaEncryption, 1.2.840.113549.1.1.1.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// id-ecPublicKey, 1.2.840.10045.2.1.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// The curve identifier that goes beside id-ecPublicKey in a SubjectPublicKeyInfo.
///
/// Only the curves with a registered identifier can be written. A TPM curve
/// with none cannot be named in a certificate at all, which is a property of
/// the key rather than of the signing scheme.
fn curve_oid(curve_id: u16) -> Option<&'static [u8]> {
    Some(match curve_id {
        // 1.2.840.10045.3.1.1
        curve::NIST_P192 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01],
        // 1.3.132.0.33
        curve::NIST_P224 => &[0x2B, 0x81, 0x04, 0x00, 0x21],
        // 1.2.840.10045.3.1.7
        curve::NIST_P256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // 1.3.132.0.34
        curve::NIST_P384 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
        // 1.3.132.0.35
        curve::NIST_P521 => &[0x2B, 0x81, 0x04, 0x00, 0x23],
        // 1.2.156.10197.1.301
        curve::SM2_P256 => &[0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D],
        _ => return None,
    })
}

/// The AlgorithmIdentifier for a signing scheme over a hash algorithm.
///
/// Part 3 clause 18.8.1: "if the caller does not provide this field and the TPM
/// does not have OID values for the signing scheme, then the TPM will return an
/// error (TPM_RC_SCHEME)", and the note beside it explains that a scheme with
/// no identifier here can still be used when the caller supplies one.
fn signature_algorithm(scheme: u16, hash_alg: u16) -> Option<Vec<u8>> {
    let oid: &[u8] = match (scheme, hash_alg) {
        // sha1WithRSAEncryption through sha512WithRSAEncryption,
        // 1.2.840.113549.1.1.{5,14,11,12,13}.
        (alg::RSASSA, alg::SHA1) => &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05],
        (alg::RSASSA, alg::SHA256) => &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
        (alg::RSASSA, alg::SHA384) => &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C],
        (alg::RSASSA, alg::SHA512) => &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D],
        // ecdsa-with-SHA1, 1.2.840.10045.4.1, then ecdsa-with-SHA2 224 to 512,
        // 1.2.840.10045.4.3.{1,2,3,4}.
        (alg::ECDSA, alg::SHA1) => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01],
        (alg::ECDSA, alg::SHA256) => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
        (alg::ECDSA, alg::SHA384) => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],
        (alg::ECDSA, alg::SHA512) => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04],
        _ => return None,
    };
    let identifier = der::tlv(tag::OID, oid);
    // RFC 4055 clause 5: an RSA PKCS#1 v1.5 identifier carries an explicit
    // NULL, and RFC 5758 clause 3.2 has an ECDSA identifier omit the field.
    Some(if scheme == alg::RSASSA {
        der::sequence(&[&identifier, &der::tlv(tag::NULL, &[])])
    } else {
        der::sequence(&[&identifier])
    })
}

/// The SubjectPublicKeyInfo of the object being certified.
fn subject_public_key_info(object: &Object) -> TpmResult<Vec<u8>> {
    match (&object.public.parameters, &object.public.unique) {
        (PublicParms::Rsa { exponent, .. }, PublicId::Rsa(modulus)) => {
            // Part 2 Table 228: an exponent of zero means the default, which
            // Part 1 clause 27.5.1 fixes at 2^16 + 1.
            let exponent = if *exponent == 0 { 65537 } else { *exponent };
            let key = der::sequence(&[
                &der::unsigned_integer(modulus.as_slice()),
                &der::unsigned_integer(&exponent.to_be_bytes()),
            ]);
            Ok(der::sequence(&[
                &der::sequence(&[
                    &der::tlv(tag::OID, OID_RSA_ENCRYPTION),
                    &der::tlv(tag::NULL, &[]),
                ]),
                &der::bit_string(&key),
            ]))
        }
        (PublicParms::Ecc { curve_id, .. }, PublicId::Ecc(point)) => {
            let oid = curve_oid(*curve_id).ok_or(TpmRc(rc::KEY).with_handle(1))?;
            // SEC 1 clause 2.3.3, the uncompressed point form, with both
            // coordinates padded to the length the curve fixes.
            let size = crate::tpm::crypto::ecc::Curve::new(*curve_id)?.coordinate_size();
            let mut encoded = Vec::with_capacity(1 + 2 * size);
            encoded.push(0x04);
            for coordinate in [point.x.as_slice(), point.y.as_slice()] {
                if coordinate.len() > size {
                    return Err(TpmRc(rc::KEY).with_handle(1));
                }
                encoded.extend(std::iter::repeat_n(0u8, size - coordinate.len()));
                encoded.extend_from_slice(coordinate);
            }
            Ok(der::sequence(&[
                &der::sequence(&[
                    &der::tlv(tag::OID, OID_EC_PUBLIC_KEY),
                    &der::tlv(tag::OID, oid),
                ]),
                &der::bit_string(&encoded),
            ]))
        }
        // A certificate names an asymmetric public key. A keyed hash or a
        // symmetric object has no such thing to put in the field.
        _ => Err(TpmRc(rc::KEY).with_handle(1)),
    }
}

/// The fields of the partial certificate the TPM has to read.
struct Partial<'a> {
    /// The signature algorithm identifier, when the caller supplied one.
    algorithm: Option<&'a [u8]>,
    /// Issuer, Validity and Subject, which the TPM passes through untouched.
    issuer: &'a [u8],
    validity: &'a [u8],
    subject: &'a [u8],
    /// The `[3]` tagged Extensions field.
    extensions: &'a [u8],
    /// The KeyUsage the Extensions field carries.
    key_usage: X509KeyUsage,
    /// The TPMA_OBJECT the Extensions field carries, when it carries one.
    object_attributes: Option<u32>,
}

/// Read the partial certificate.
///
/// Part 3 clause 18.8.1: the caller provides "four or five of the elements
/// enumerated above in a DER encoded SEQUENCE", the optional signature
/// algorithm identifier first, then Issuer, Validity, Subject Name and
/// Extensions, and "the TPM determines if the Signature Algorithm Identifier
/// element is present by counting the elements".
fn parse_partial(certificate: &[u8]) -> TpmResult<Partial<'_>> {
    let mut outer = der::Reader::new(certificate);
    let sequence = outer.tagged(tag::SEQUENCE)?;
    if !outer.is_empty() {
        return Err(TpmRc(rc::VALUE));
    }
    let mut fields = der::Reader::new(sequence.value);
    let mut elements = Vec::new();
    while !fields.is_empty() {
        elements.push(fields.element()?);
        if elements.len() > 5 {
            return Err(TpmRc(rc::VALUE));
        }
    }
    let (algorithm, rest) = match elements.len() {
        4 => (None, &elements[..]),
        5 => (Some(elements[0].raw), &elements[1..]),
        _ => return Err(TpmRc(rc::VALUE)),
    };
    // RFC 5280 clause 4.1 writes the extensions as "[3] EXPLICIT Extensions",
    // and the three fields before it are each a SEQUENCE.
    if rest[3].tag != tag::context(3) {
        return Err(TpmRc(rc::VALUE));
    }
    let mut explicit = der::Reader::new(rest[3].value);
    let extensions = explicit.tagged(tag::SEQUENCE)?;
    if !explicit.is_empty() {
        return Err(TpmRc(rc::VALUE));
    }

    let mut key_usage = None;
    let mut object_attributes = None;
    let mut each = der::Reader::new(extensions.value);
    while !each.is_empty() {
        let extension = each.tagged(tag::SEQUENCE)?;
        let mut parts = der::Reader::new(extension.value);
        let oid = parts.tagged(tag::OID)?;
        // RFC 5280 clause 4.1: an Extension is the identifier, an optional
        // BOOLEAN critical that defaults to FALSE, and the OCTET STRING that
        // holds the DER of the value.
        let mut body = parts.element()?;
        if body.tag == 0x01 {
            body = parts.element()?;
        }
        if body.tag != tag::OCTET_STRING || !parts.is_empty() {
            return Err(TpmRc(rc::VALUE));
        }
        if oid.value == OID_KEY_USAGE {
            let mut inner = der::Reader::new(body.value);
            let bits = inner.tagged(tag::BIT_STRING)?;
            if !inner.is_empty() {
                return Err(TpmRc(rc::VALUE));
            }
            key_usage = Some(X509KeyUsage(der::bit_field(bits.value)?));
        } else if oid.value == OID_TPMA_OBJECT {
            // The same clause: "it is a SEQUENCE containing that OID and an
            // OCTET STRING encapsulating a 4-byte BIT STRING holding the big
            // endian TPMA_OBJECT."
            let mut inner = der::Reader::new(body.value);
            let bits = inner.tagged(tag::BIT_STRING)?;
            if !inner.is_empty() || bits.value.len() != 5 || bits.value[0] != 0 {
                return Err(TpmRc(rc::VALUE));
            }
            object_attributes = Some(u32::from_be_bytes([
                bits.value[1],
                bits.value[2],
                bits.value[3],
                bits.value[4],
            ]));
        }
    }

    // "The Extensions element is required to contain a Key Usage extension."
    let key_usage = key_usage.ok_or(TpmRc(rc::VALUE).with_parameter(3))?;
    Ok(Partial {
        algorithm,
        issuer: rest[0].raw,
        validity: rest[1].raw,
        subject: rest[2].raw,
        extensions: rest[3].raw,
        key_usage,
        object_attributes,
    })
}

/// Check the KeyUsage against the object, as Part 2 Table 45 requires.
fn check_key_usage(usage: X509KeyUsage, attributes: ObjectAttributes) -> TpmResult<()> {
    let sign = attributes.has(ObjectAttributes::SIGN_ENCRYPT);
    let decrypt = attributes.has(ObjectAttributes::DECRYPT);
    let restricted = attributes.has(ObjectAttributes::RESTRICTED);
    let fixed_tpm = attributes.has(ObjectAttributes::FIXED_TPM);
    // Table 45 gives each bit the attribute the object has to carry for it.
    // keyEncipherment asks for more than one: "asymmetric key with
    // Attributes.decrypt and Attributes.restricted SET - key has the attributes
    // of a parent key".
    let required = [
        (X509KeyUsage::DECIPHER_ONLY, decrypt),
        (X509KeyUsage::ENCIPHER_ONLY, decrypt),
        (X509KeyUsage::CRL_SIGN, sign),
        (X509KeyUsage::KEY_CERT_SIGN, sign),
        (X509KeyUsage::KEY_AGREEMENT, decrypt),
        (X509KeyUsage::DATA_ENCIPHERMENT, decrypt),
        (X509KeyUsage::KEY_ENCIPHERMENT, decrypt && restricted),
        (X509KeyUsage::NON_REPUDIATION, fixed_tpm),
        (X509KeyUsage::DIGITAL_SIGNATURE, sign),
    ];
    for (bit, allowed) in required {
        if usage.has(bit) && !allowed {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(3));
        }
    }
    Ok(())
}

/// TPM2_CertifyX509, Part 3 clause 18.8.
pub fn certify_x509(state: &mut TpmState, request: &Request) -> TpmResult<Response> {
    let object_handle = request.handle(0)?;
    let sign_handle = request.handle(1)?;
    let mut r = request.reader();
    let reserved = Tpm2bData::unmarshal(&mut r).map_err(|e| e.with_parameter(1))?;
    let in_scheme = Scheme::unmarshal_sig_scheme(&mut r).map_err(|e| e.with_parameter(2))?;
    let partial = Tpm2bMaxBuffer::unmarshal(&mut r).map_err(|e| e.with_parameter(3))?;
    r.expect_end()?;

    // Table 109 says of the first parameter that it "shall be an Empty Buffer".
    if !reserved.as_slice().is_empty() {
        return Err(TpmRc(rc::VALUE).with_parameter(1));
    }

    // Clause 18.8.1: "if objectHandle does not have a sensitive area loaded,
    // the TPM will return an error (TPM_RC_AUTH_UNAVAILABLE)". A persistent or
    // transient object that was loaded with its public area alone has no
    // authorization value, so the ADMIN role authorization means nothing.
    let object = if crate::tpm::core::object::ObjectSlots::is_transient(object_handle) {
        state
            .objects
            .object(object_handle)
            .map_err(|e| e.with_handle(1))?
            .clone()
    } else {
        state
            .persistent
            .get(&object_handle)
            .ok_or(TpmRc(rc::HANDLE).with_handle(1))?
            .clone()
    };
    if object.sensitive.is_none() {
        return Err(TpmRc(rc::AUTH_UNAVAILABLE).with_handle(1));
    }

    // "signHandle is required to have the sign attribute SET (TPM_RC_KEY)."
    let signer = super::attest::signing_object(state, sign_handle)
        .map_err(|e| e.with_handle(2))?;
    let scheme = super::crypto::signing_scheme_at(&signer, &in_scheme, 2)?;
    let hash_alg = scheme.hash_alg().ok_or(TpmRc(rc::SCHEME).with_parameter(2))?;

    let fields = parse_partial(partial.as_slice()).map_err(|e| e.with_parameter(3))?;
    check_key_usage(fields.key_usage, object.public.object_attributes)?;
    // "The Extensions element may contain a TPMA_OBJECT extension. If present,
    // the TPM will extract the value and verify that the extension value
    // exactly matches the TPMA_OBJECT of objectKey (TPM_RC_ATTRIBUTES)."
    if let Some(claimed) = fields.object_attributes {
        if claimed != object.public.object_attributes.0 {
            return Err(TpmRc(rc::ATTRIBUTES).with_parameter(3));
        }
    }

    // The TPM creates the version, the serial number, the subject public key
    // info and, when the caller left it out, the signature algorithm.
    //
    // RFC 5280 clause 4.1.2.1 writes the version as "[0] EXPLICIT Version
    // DEFAULT v1", and clause 18.8.1 asks for "integer value of 2 indicating
    // version 3". Clause 4.1.2.2 requires a positive serial number of at most
    // twenty octets, which is drawn here so that two certificates over the same
    // partial certificate do not collide.
    let version = der::context(0, &[&der::unsigned_integer(&[2])]);
    let mut serial = {
        use crate::tpm::crypto::rand::Rng;
        state.rng.bytes(20)?
    };
    // A leading octet below 0x80 keeps the value positive and its first octet
    // non-zero, which is the shortest DER form of a twenty octet serial.
    serial[0] = (serial[0] & 0x7F) | 0x01;
    let serial = der::unsigned_integer(&serial);
    let spki = subject_public_key_info(&object)?;

    let algorithm = match fields.algorithm {
        Some(supplied) => supplied.to_vec(),
        None => signature_algorithm(scheme.scheme, hash_alg)
            .ok_or(TpmRc(rc::SCHEME).with_parameter(2))?,
    };

    // "The TPM-created values will be returned in addedToCertificate. If the
    // TPM creates the Signature Algorithm Identifier, it will be in
    // addedToCertificate before the Subject Public Key Info."
    let added = if fields.algorithm.is_some() {
        der::sequence(&[&version, &serial, &spki])
    } else {
        der::sequence(&[&version, &serial, &algorithm, &spki])
    };

    // RFC 5280 clause 4.1 fixes the order of a TBSCertificate.
    let tbs = der::sequence(&[
        &version,
        &serial,
        &algorithm,
        fields.issuer,
        fields.validity,
        fields.subject,
        &spki,
        fields.extensions,
    ]);
    let digest = hash::digest(hash_alg, &tbs)?;
    let signature = super::crypto::sign_digest(
        state,
        &signer,
        &scheme,
        &digest,
        super::crypto::SignParameters::at(0, 2),
    )?;

    let added = Tpm2bMaxBuffer::new(added).map_err(|_| TpmRc(rc::SIZE).with_parameter(3))?;
    let tbs_digest = Tpm2bDigest::new(digest)?;
    respond(move |w| {
        added.marshal(w);
        tbs_digest.marshal(w);
        signature.marshal(w);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(bits: u32) -> ObjectAttributes {
        ObjectAttributes(bits)
    }

    #[test]
    fn a_key_usage_is_held_to_the_attributes_table_45_names() {
        let signing = attributes(ObjectAttributes::SIGN_ENCRYPT);
        assert!(check_key_usage(X509KeyUsage(X509KeyUsage::DIGITAL_SIGNATURE), signing).is_ok());
        assert!(check_key_usage(X509KeyUsage(X509KeyUsage::CRL_SIGN), signing).is_ok());
        assert!(check_key_usage(X509KeyUsage(X509KeyUsage::KEY_CERT_SIGN), signing).is_ok());
        // decrypt is CLEAR, so nothing that asks for it is allowed.
        for bit in [
            X509KeyUsage::DECIPHER_ONLY,
            X509KeyUsage::ENCIPHER_ONLY,
            X509KeyUsage::KEY_AGREEMENT,
            X509KeyUsage::DATA_ENCIPHERMENT,
            X509KeyUsage::KEY_ENCIPHERMENT,
        ] {
            assert_eq!(
                check_key_usage(X509KeyUsage(bit), signing).unwrap_err(),
                TpmRc(rc::ATTRIBUTES).with_parameter(3),
                "bit {bit:#x}"
            );
        }
        // nonRepudiation asks for fixedTPM, not for sign.
        assert_eq!(
            check_key_usage(X509KeyUsage(X509KeyUsage::NON_REPUDIATION), signing).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_parameter(3)
        );
    }

    #[test]
    fn key_encipherment_needs_a_parent_and_not_just_a_decryption_key() {
        let plain = attributes(ObjectAttributes::DECRYPT);
        assert_eq!(
            check_key_usage(X509KeyUsage(X509KeyUsage::KEY_ENCIPHERMENT), plain).unwrap_err(),
            TpmRc(rc::ATTRIBUTES).with_parameter(3)
        );
        let parent = attributes(ObjectAttributes::DECRYPT | ObjectAttributes::RESTRICTED);
        assert!(check_key_usage(X509KeyUsage(X509KeyUsage::KEY_ENCIPHERMENT), parent).is_ok());
    }

    #[test]
    fn the_signature_algorithm_is_written_for_the_schemes_with_an_identifier() {
        let rsa = signature_algorithm(alg::RSASSA, alg::SHA256).unwrap();
        // sha256WithRSAEncryption carries an explicit NULL.
        assert_eq!(rsa.last(), Some(&0x00));
        let ecdsa = signature_algorithm(alg::ECDSA, alg::SHA256).unwrap();
        let mut r = der::Reader::new(&ecdsa);
        let outer = r.tagged(tag::SEQUENCE).unwrap();
        let mut inner = der::Reader::new(outer.value);
        assert_eq!(
            inner.tagged(tag::OID).unwrap().value,
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        );
        assert!(inner.is_empty(), "an ECDSA identifier omits the parameters");
        // A scheme with no identifier is what clause 18.8.1 answers
        // TPM_RC_SCHEME for.
        assert!(signature_algorithm(alg::RSAPSS, alg::SHA256).is_none());
        assert!(signature_algorithm(alg::ECDAA, alg::SHA256).is_none());
    }
}
