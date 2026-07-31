//! A debug console for looking at and changing the TPM directly.
//!
//! The command interface only shows what the specification lets it show. A
//! PCR that no policy references, the working state of the random number
//! generator and the private half of a loaded key are all invisible from
//! outside, which makes a failure hard to follow. This console reaches the
//! same state a command reaches, under the same lock, and reports it.
//!
//! Nothing here is a TPM command. The console does not check authorization,
//! it does not audit, and it can put the TPM in a state no sequence of
//! commands could reach. It is a debugging aid and is off unless the daemon
//! was started with `--console`.

use std::io::{BufRead, Write};
use std::sync::Arc;

use crate::logging::Logger;
use crate::tpm::constants::alg;
use crate::tpm::core::state::TpmState;
use crate::tpm::crypto::rand::Rng;
use crate::tpm::device::Tpm;
use crate::util::hex;

/// What the console should do after a line.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Text to print.
    Output(String),
    /// The line asked to leave the console.
    Quit,
}

/// Text printed for `help`.
pub const HELP: &str = "\
commands:
  status                                power, startup and lockout state
  banks                                 allocated PCR banks

  pcr list [alg]                        every register in a bank
  pcr read <index> [alg]                one register
  pcr extend <index> <hex> [alg]        extend a register with a digest
  pcr write <index> <hex> [alg]         put a digest straight into a register
  pcr reset <index>                     reset a register in every bank

  nv list                               defined indexes
  nv read <handle> [offset] [size]      read index data
  nv write <handle> <offset> <hex>      write index data
  nv undefine <handle>                  remove an index

  rng show                              DRBG working state and reseed counter
  rng seed <hex>                        reseed the DRBG
  rng stir <hex>                        add data to the DRBG without reseeding
  rng bytes <count>                     draw octets from the DRBG

  key list                              loaded and persistent objects
  key show <handle>                     public area, name and private values
  key auth <handle> <hex>               set the authorization value
  key flush <handle>                    remove a loaded object

  save                                  write the state file now
  help                                  this text
  quit                                  leave the console
";

/// Longest console line accepted, in octets.
///
/// A line is read into memory before anything looks at it, so it needs a bound
/// of its own. This is far more than any command below needs: the longest is a
/// 4096 bit RSA modulus written as hex, which is 1024 characters.
pub const MAX_LINE: usize = 8 * 1024;

/// Largest digest this TPM implements, which bounds every digest argument.
const MAX_DIGEST: usize = crate::tpm::structures::base::MAX_DIGEST_SIZE;

/// Largest amount of entropy a console line may feed the generator.
const MAX_STIR: usize = 1024;

/// Read one line, refusing one longer than [`MAX_LINE`].
///
/// Returns `None` at end of input. A line that is too long is dropped and the
/// rest of it is discarded, so the next read starts at the following line
/// rather than part way through the one that was refused.
fn read_line<R: BufRead>(input: &mut R) -> std::io::Result<Option<Result<String, ()>>> {
    let mut buf = Vec::new();
    // Set once the line has passed the limit. The rest of it is still read, so
    // the next line starts where it should, but none of it is kept.
    let mut too_long = false;
    let mut any = false;

    loop {
        // What the reader already holds is examined first, then consumed, so
        // the borrow of the buffer ends before the reader is advanced.
        let (upto, used, done) = {
            let available = match input.fill_buf() {
                Ok(b) => b,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                break;
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => (i, i + 1, true),
                None => (available.len(), available.len(), false),
            }
        };
        any = true;
        if !too_long {
            if buf.len() + upto > MAX_LINE {
                too_long = true;
                buf = Vec::new();
            } else {
                let available = input.fill_buf()?;
                buf.extend_from_slice(&available[..upto]);
            }
        }
        input.consume(used);
        if done {
            break;
        }
    }

    if !any {
        return Ok(None);
    }
    if too_long {
        return Ok(Some(Err(())));
    }
    // A line ending may be either form, and the carriage return is not part of
    // the text.
    while buf.ends_with(b"\r") {
        buf.pop();
    }
    Ok(Some(Ok(String::from_utf8_lossy(&buf).into_owned())))
}

/// Read lines from `input` and act on them until it ends or `quit` is given.
pub fn serve<R: BufRead, W: Write>(
    tpm: &Tpm,
    logger: &Logger,
    mut input: R,
    mut output: W,
) -> std::io::Result<()> {
    write!(output, "swtrust console. Type help for the command list.\n> ")?;
    output.flush()?;
    while let Some(line) = read_line(&mut input)? {
        let line = match line {
            Ok(line) => line,
            Err(()) => {
                writeln!(output, "error: a line may be at most {MAX_LINE} characters")?;
                write!(output, "> ")?;
                output.flush()?;
                continue;
            }
        };
        logger.line(&format!("console: {line}"));
        match execute(tpm, &line) {
            Outcome::Quit => {
                writeln!(output, "leaving the console")?;
                return Ok(());
            }
            Outcome::Output(text) => {
                if !text.is_empty() {
                    writeln!(output, "{text}")?;
                }
            }
        }
        write!(output, "> ")?;
        output.flush()?;
    }
    Ok(())
}

/// Start the console on its own thread.
///
/// The handle is passed rather than a lock on it. A lock held across the read
/// of the next line would be held while the console sits idle, and with
/// --verbose the transport writes its log to the same stream, so a command
/// arriving while nobody is typing would wait for a person.
pub fn spawn(tpm: Arc<Tpm>, logger: Arc<Logger>) {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        if let Err(e) = serve(&tpm, &logger, stdin.lock(), std::io::stdout()) {
            logger.line(&format!("console ended: {e}"));
        }
    });
}

/// Act on one console line.
pub fn execute(tpm: &Tpm, line: &str) -> Outcome {
    let words: Vec<&str> = line.split_whitespace().collect();
    let Some(&head) = words.first() else {
        return Outcome::Output(String::new());
    };
    match head {
        "quit" | "exit" => Outcome::Quit,
        "help" => Outcome::Output(HELP.to_string()),
        "status" => Outcome::Output(status(tpm)),
        "banks" => Outcome::Output(banks(tpm)),
        "pcr" => Outcome::Output(unwrap(pcr(tpm, &words[1..]))),
        "nv" => Outcome::Output(unwrap(nv(tpm, &words[1..]))),
        "rng" => Outcome::Output(unwrap(rng(tpm, &words[1..]))),
        "key" => Outcome::Output(unwrap(key(tpm, &words[1..]))),
        "save" => {
            tpm.persist();
            Outcome::Output("state written".to_string())
        }
        other => Outcome::Output(format!("unknown command {other}, try help")),
    }
}

/// Report an error as text, because the console never stops on one.
fn unwrap(r: Result<String, String>) -> String {
    match r {
        Ok(s) => s,
        Err(e) => format!("error: {e}"),
    }
}

fn status(tpm: &Tpm) -> String {
    let powered = crate::server::Device::is_powered_on(tpm);
    tpm.with_state(|s| {
        let mut out = String::new();
        out.push_str(&format!("powered        {powered}\n"));
        out.push_str(&format!("started        {}\n", s.started));
        out.push_str(&format!("failure mode   {}\n", s.failure_mode));
        out.push_str(&format!("self test done {}\n", s.self_test_done));
        out.push_str(&format!("nv available   {}\n", s.nv_available));
        out.push_str(&format!("locality       {}\n", s.locality));
        out.push_str(&format!("phys presence  {}\n", s.physical_presence));
        out.push_str(&format!("lockout count  {}\n", s.lockout.failed_tries));
        out.push_str(&format!("pcr counter    {}\n", s.pcr.update_counter()));
        out.push_str(&format!("loaded objects {}\n", s.objects.len()));
        out.push_str(&format!("persistent     {}\n", s.persistent.len()));
        out.push_str(&format!("nv indexes     {}\n", s.nv.len()));
        out.push_str(&format!("sessions       {}", s.sessions.len()));
        out
    })
}

fn banks(tpm: &Tpm) -> String {
    tpm.with_state(|s| {
        let names: Vec<String> = s.pcr.algorithms().iter().map(|a| alg_name(*a)).collect();
        format!("allocated banks: {}", names.join(" "))
    })
}

/// The bank a command names.
///
/// With none named the SHA-256 bank is used when it is allocated, because that
/// is the one a caller almost always means, and otherwise the first allocated
/// bank so the console still answers on a TPM without it.
fn bank_of(state: &TpmState, given: Option<&str>) -> Result<u16, String> {
    if let Some(text) = given {
        return alg_value(text).ok_or(format!("unknown hash algorithm {text}"));
    }
    let allocated = state.pcr.algorithms();
    if allocated.contains(&alg::SHA256) {
        return Ok(alg::SHA256);
    }
    allocated
        .first()
        .copied()
        .ok_or("no PCR bank is allocated".to_string())
}

fn pcr(tpm: &Tpm, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        Some("list") => tpm.with_state(|s| {
            let bank = bank_of(s, args.get(1).copied())?;
            let mut out = String::new();
            for index in 0..crate::tpm::config::IMPLEMENTATION_PCR {
                let value = s
                    .pcr
                    .read(bank, index)
                    .map_err(|e| format!("PCR {index}: {}", code(e)))?;
                out.push_str(&format!("{index:2} {}\n", hex::encode(value)));
            }
            out.pop();
            Ok(out)
        }),
        Some("read") => {
            let index = number_u16(args.get(1).copied(), "index")?;
            tpm.with_state(|s| {
                let bank = bank_of(s, args.get(2).copied())?;
                let value = s.pcr.read(bank, index).map_err(|e| code(e))?;
                Ok(hex::encode(value))
            })
        }
        Some("extend") => {
            let index = number_u16(args.get(1).copied(), "index")?;
            let digest = bytes(args.get(2).copied(), "digest", MAX_DIGEST)?;
            tpm.with_state_mut(|s| {
                let bank = bank_of(s, args.get(3).copied())?;
                s.pcr
                    .extend_one(bank, index, &digest)
                    .map_err(|e| code(e))?;
                let value = s.pcr.read(bank, index).map_err(|e| code(e))?;
                Ok(format!("{index} now {}", hex::encode(value)))
            })
        }
        Some("write") => {
            let index = number_u16(args.get(1).copied(), "index")?;
            let digest = bytes(args.get(2).copied(), "digest", MAX_DIGEST)?;
            tpm.with_state_mut(|s| {
                let bank = bank_of(s, args.get(3).copied())?;
                s.pcr.set(bank, index, &digest).map_err(|e| code(e))?;
                Ok(format!("{index} set to {}", hex::encode(&digest)))
            })
        }
        Some("reset") => {
            let index = number_u16(args.get(1).copied(), "index")?;
            tpm.with_state_mut(|s| {
                // The console is not bound by the locality a command would
                // need, so the reset is made from the locality the register
                // allows.
                let locality = reset_locality(index)?;
                s.pcr.reset(index, locality).map_err(|e| code(e))?;
                Ok(format!("{index} reset"))
            })
        }
        _ => Err("try pcr list, read, extend, write or reset".to_string()),
    }
}

/// A locality the register allows a reset from.
fn reset_locality(index: u16) -> Result<u8, String> {
    let allowed = crate::tpm::core::pcr::attributes(index).reset_locality;
    (0..=4u8)
        .find(|l| allowed & (1 << l) != 0)
        .ok_or(format!("PCR {index} cannot be reset"))
}

fn nv(tpm: &Tpm, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        Some("list") => tpm.with_state(|s| {
            if s.nv.is_empty() {
                return Ok("no index is defined".to_string());
            }
            let mut out = String::new();
            for (handle, index) in s.nv.iter() {
                out.push_str(&format!(
                    "{handle:08x} size {:<5} written {:<5} type {} attrs {:08x}\n",
                    index.public.data_size,
                    index.written(),
                    index.index_type(),
                    index.public.attributes.0,
                ));
            }
            out.pop();
            Ok(out)
        }),
        Some("read") => {
            let handle = number(args.get(1).copied(), "handle")?;
            let offset = match args.get(2) {
                Some(v) => number_u16(Some(v), "offset")?,
                None => 0,
            };
            // Every argument is checked before the state is looked at, so a
            // line reports what is wrong with itself rather than reporting the
            // first thing the TPM happens to object to.
            let given_size = match args.get(3) {
                Some(v) => Some(number_u16(Some(v), "size")?),
                None => None,
            };
            tpm.with_state(|s| {
                let index = s.nv.get(handle).map_err(|e| code(e))?;
                let size = match given_size {
                    Some(v) => v,
                    None => index.public.data_size.saturating_sub(offset),
                };
                let data = index.read(offset, size).map_err(|e| code(e))?;
                Ok(hex::encode(&data))
            })
        }
        Some("write") => {
            let handle = number(args.get(1).copied(), "handle")?;
            let offset = number_u16(args.get(2).copied(), "offset")?;
            let data = bytes(args.get(3).copied(), "data", crate::tpm::config::MAX_NV_INDEX_SIZE)?;
            tpm.with_state_mut(|s| {
                let index = s.nv.get_mut(handle).map_err(|e| code(e))?;
                index.write(offset, &data).map_err(|e| code(e))?;
                Ok(format!("wrote {} octets", data.len()))
            })
        }
        Some("undefine") => {
            let handle = number(args.get(1).copied(), "handle")?;
            tpm.with_state_mut(|s| {
                s.nv.undefine(handle).map_err(|e| code(e))?;
                Ok(format!("{handle:08x} removed"))
            })
        }
        _ => Err("try nv list, read, write or undefine".to_string()),
    }
}

fn rng(tpm: &Tpm, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        Some("show") => tpm.with_state(|s| {
            Ok(format!(
                "key            {}\nvalue          {}\nreseed counter {}\nneeds reseed   {}",
                hex::encode(s.rng.key()),
                hex::encode(s.rng.value()),
                s.rng.reseed_counter(),
                s.rng.needs_reseed(),
            ))
        }),
        Some("seed") => {
            let entropy = bytes(args.get(1).copied(), "entropy", MAX_STIR)?;
            tpm.with_state_mut(|s| {
                s.rng.reseed(&entropy).map_err(|e| code(e))?;
                Ok(format!("reseeded, counter {}", s.rng.reseed_counter()))
            })
        }
        Some("stir") => {
            let data = bytes(args.get(1).copied(), "data", MAX_STIR)?;
            tpm.with_state_mut(|s| {
                s.rng.stir(&data).map_err(|e| code(e))?;
                Ok("stirred".to_string())
            })
        }
        Some("bytes") => {
            let count = number(args.get(1).copied(), "count")? as usize;
            if count > crate::tpm::config::MAX_DIGEST_BUFFER {
                return Err(format!(
                    "at most {} octets at a time",
                    crate::tpm::config::MAX_DIGEST_BUFFER
                ));
            }
            tpm.with_state_mut(|s| {
                let out = s.rng.bytes(count).map_err(|e| code(e))?;
                Ok(hex::encode(&out))
            })
        }
        _ => Err("try rng show, seed, stir or bytes".to_string()),
    }
}

fn key(tpm: &Tpm, args: &[&str]) -> Result<String, String> {
    match args.first().copied() {
        Some("list") => tpm.with_state(|s| {
            let mut out = String::new();
            for handle in s.objects.handles() {
                let line = match s.objects.object(handle) {
                    Ok(o) => format!(
                        "{handle:08x} transient  {} {} {}",
                        alg_name(o.public.object_type),
                        alg_name(o.public.name_alg),
                        if o.is_public_only() { "public" } else { "private" }
                    ),
                    // A sequence holds no key, so it is listed as itself.
                    Err(_) => format!("{handle:08x} transient  sequence"),
                };
                out.push_str(&line);
                out.push('\n');
            }
            for (handle, o) in s.persistent.iter() {
                out.push_str(&format!(
                    "{handle:08x} persistent {} {} {}\n",
                    alg_name(o.public.object_type),
                    alg_name(o.public.name_alg),
                    if o.is_public_only() { "public" } else { "private" }
                ));
            }
            if out.is_empty() {
                return Ok("no object is loaded".to_string());
            }
            out.pop();
            Ok(out)
        }),
        Some("show") => {
            let handle = number(args.get(1).copied(), "handle")?;
            tpm.with_state(|s| {
                let object = find_object(s, handle)?;
                Ok(describe_object(object))
            })
        }
        Some("auth") => {
            let handle = number(args.get(1).copied(), "handle")?;
            let value = bytes(args.get(2).copied(), "auth", MAX_DIGEST)?;
            let limit = crate::tpm::crypto::hash::digest_size(alg::SHA512).unwrap_or(64);
            if value.len() > limit {
                return Err(format!("an authorization value is at most {limit} octets"));
            }
            tpm.with_state_mut(|s| {
                let object = find_object_mut(s, handle)?;
                let Some(sensitive) = object.sensitive.as_mut() else {
                    return Err("the object has no sensitive area".to_string());
                };
                sensitive.auth_value =
                    crate::tpm::structures::base::Tpm2bDigest::new(value.clone())
                        .map_err(|e| code(e))?;
                Ok(format!("{handle:08x} authorization set"))
            })
        }
        Some("flush") => {
            let handle = number(args.get(1).copied(), "handle")?;
            tpm.with_state_mut(|s| {
                s.objects.remove(handle).map_err(|e| code(e))?;
                Ok(format!("{handle:08x} flushed"))
            })
        }
        _ => Err("try key list, show, auth or flush".to_string()),
    }
}

fn find_object(s: &TpmState, handle: u32) -> Result<&crate::tpm::core::object::Object, String> {
    if let Some(o) = s.persistent.get(&handle) {
        return Ok(o);
    }
    s.objects.object(handle).map_err(|e| code(e))
}

fn find_object_mut(
    s: &mut TpmState,
    handle: u32,
) -> Result<&mut crate::tpm::core::object::Object, String> {
    if s.persistent.contains_key(&handle) {
        return s
            .persistent
            .get_mut(&handle)
            .ok_or("no such object".to_string());
    }
    match s.objects.get_mut(handle).map_err(|e| code(e))? {
        crate::tpm::core::object::Slot::Object(o) => Ok(o.as_mut()),
        _ => Err("the handle names a sequence, not a key".to_string()),
    }
}

fn describe_object(o: &crate::tpm::core::object::Object) -> String {
    use crate::tpm::structures::keys::{PublicId, PublicParms, SensitiveComposite};
    let mut out = String::new();
    out.push_str(&format!("type           {}\n", alg_name(o.public.object_type)));
    out.push_str(&format!("nameAlg        {}\n", alg_name(o.public.name_alg)));
    out.push_str(&format!("attributes     {:08x}\n", o.public.object_attributes.0));
    out.push_str(&format!("hierarchy      {:08x}\n", o.hierarchy));
    out.push_str(&format!("tpmGenerated   {}\n", o.tpm_generated));
    out.push_str(&format!("name           {}\n", hex::encode(&o.name)));
    out.push_str(&format!(
        "qualifiedName  {}\n",
        hex::encode(&o.qualified_name)
    ));
    out.push_str(&format!(
        "authPolicy     {}\n",
        hex::encode(o.public.auth_policy.as_slice())
    ));
    match &o.public.parameters {
        PublicParms::Rsa { key_bits, exponent, .. } => {
            let e = if *exponent == 0 { 65537 } else { *exponent };
            out.push_str(&format!("keyBits        {key_bits}\nexponent       {e}\n"));
        }
        PublicParms::Ecc { curve_id, .. } => {
            out.push_str(&format!("curve          {curve_id:#06x}\n"));
        }
        PublicParms::SymCipher { sym } => {
            out.push_str(&format!(
                "symmetric      {} {} bits\n",
                alg_name(sym.algorithm),
                sym.key_bits
            ));
        }
        PublicParms::KeyedHash { .. } => {}
    }
    match &o.public.unique {
        PublicId::Rsa(m) => out.push_str(&format!("modulus        {}\n", hex::encode(m.as_slice()))),
        PublicId::Ecc(p) => {
            out.push_str(&format!("x              {}\n", hex::encode(p.x.as_slice())));
            out.push_str(&format!("y              {}\n", hex::encode(p.y.as_slice())));
        }
        PublicId::KeyedHash(d) => {
            out.push_str(&format!("unique         {}\n", hex::encode(d.as_slice())))
        }
        PublicId::Sym(d) => out.push_str(&format!("unique         {}\n", hex::encode(d.as_slice()))),
        // Only a derivation parent carries these, and never once loaded.
        PublicId::Derive(_) => out.push_str("unique         derivation values\n"),
    }
    match &o.sensitive {
        None => out.push_str("sensitive      absent, the object is public only"),
        Some(s) => {
            out.push_str(&format!(
                "authValue      {}\n",
                hex::encode(s.auth_value.as_slice())
            ));
            out.push_str(&format!(
                "seedValue      {}\n",
                hex::encode(s.seed_value.as_slice())
            ));
            let (label, value) = match &s.sensitive {
                SensitiveComposite::Rsa(p) => ("prime", p.as_slice()),
                SensitiveComposite::Ecc(d) => ("private", d.as_slice()),
                SensitiveComposite::Bits(b) => ("bits", b.as_slice()),
                SensitiveComposite::Sym(k) => ("key", k.as_slice()),
            };
            out.push_str(&format!("{label:14} {}", hex::encode(value)));
        }
    }
    out
}

/// A number given in decimal, or in hex with a leading 0x.
fn number(text: Option<&str>, what: &str) -> Result<u32, String> {
    let text = text.ok_or(format!("{what} is needed"))?;
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(rest) => u32::from_str_radix(rest, 16),
        None => text.parse::<u32>(),
    };
    parsed.map_err(|_| format!("{what} {text} is not a number"))
}

/// A number that has to fit in a u16, so a cast cannot change which register
/// or offset the line meant.
fn number_u16(text: Option<&str>, what: &str) -> Result<u16, String> {
    let value = number(text, what)?;
    u16::try_from(value).map_err(|_| format!("{what} {value} is too large"))
}

/// Octets given as hex, at most `max` of them.
///
/// The length is checked before decoding, so a long argument is refused rather
/// than allocated and then rejected.
fn bytes(text: Option<&str>, what: &str, max: usize) -> Result<Vec<u8>, String> {
    let text = text.ok_or(format!("{what} is needed"))?;
    if text.len() > max * 2 {
        return Err(format!("{what} is at most {max} octets"));
    }
    hex::decode(text).map_err(|_| format!("{what} is not hex"))
}

/// A response code as text, so a console line reports what a command would.
fn code(e: crate::tpm::error::TpmRc) -> String {
    format!("{:08x}", e.value())
}

/// The short name of an algorithm, falling back to its value.
fn alg_name(value: u16) -> String {
    match value {
        alg::RSA => "rsa".to_string(),
        alg::ECC => "ecc".to_string(),
        alg::KEYEDHASH => "keyedhash".to_string(),
        alg::SYMCIPHER => "symcipher".to_string(),
        alg::SHA1 => "sha1".to_string(),
        alg::SHA256 => "sha256".to_string(),
        alg::SHA384 => "sha384".to_string(),
        alg::SHA512 => "sha512".to_string(),
        alg::SM3_256 => "sm3_256".to_string(),
        alg::AES => "aes".to_string(),
        alg::NULL => "null".to_string(),
        other => format!("{other:#06x}"),
    }
}

/// The algorithm a name stands for.
fn alg_value(name: &str) -> Option<u16> {
    match name {
        "sha1" => Some(alg::SHA1),
        "sha256" => Some(alg::SHA256),
        "sha384" => Some(alg::SHA384),
        "sha512" => Some(alg::SHA512),
        _ => None,
    }
}
