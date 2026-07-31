//! A check that every command reads its whole parameter area.
//!
//! Part 3 clause 5.8.2 answers TPM_RC_SIZE when a command carries surplus
//! parameter octets, and clause 5.6 leaves the TPM unchanged when a command
//! fails. Both are satisfied by calling [`crate::tpm::marshal::Reader::expect_end`]
//! once a command has read what its schematic defines and before it changes
//! anything.
//!
//! The dispatcher checks again after the action, so a command that forgets is
//! still refused, but only once it has already run. This module holds a test
//! that reads the command sources and requires the call to be present and in
//! the right place, which is the part the dispatcher cannot see.

#[cfg(test)]
mod tests {
    /// The command modules, as source, paired with their names.
    const SOURCES: &[(&str, &str)] = &[
        ("attest.rs", include_str!("attest.rs")),
        ("context.rs", include_str!("context.rs")),
        ("crypto.rs", include_str!("crypto.rs")),
        ("duplication.rs", include_str!("duplication.rs")),
        ("hierarchy.rs", include_str!("hierarchy.rs")),
        ("management.rs", include_str!("management.rs")),
        ("nv.rs", include_str!("nv.rs")),
        ("object.rs", include_str!("object.rs")),
        ("pcr.rs", include_str!("pcr.rs")),
        ("policy.rs", include_str!("policy.rs")),
        ("signing.rs", include_str!("signing.rs")),
    ];

    /// The bodies of the public command functions in one module.
    fn command_bodies(source: &str) -> Vec<(String, String)> {
        // Everything before the test module is the command code.
        let source = match source.find("#[cfg(test)]") {
            Some(i) => &source[..i],
            None => source,
        };
        let mut out = Vec::new();
        let mut rest = source;
        while let Some(i) = rest.find("\npub fn ") {
            let after = &rest[i + 8..];
            let name: String = after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            // The body runs to the next line that closes at column zero.
            let body_end = after.find("\n}\n").map(|e| e + 3).unwrap_or(after.len());
            out.push((name, after[..body_end].to_string()));
            rest = &after[body_end.saturating_sub(1)..];
        }
        out
    }

    #[test]
    fn every_command_checks_the_end_of_its_parameters() {
        let mut problems = Vec::new();
        for (file, source) in SOURCES {
            for (name, body) in command_bodies(source) {
                if !body.contains("request.reader()") {
                    continue;
                }
                match body.find("r.expect_end()?;") {
                    None => problems.push(format!("{file}::{name} never checks")),
                    Some(at) => {
                        // No parameter may be read after the check, or the
                        // check would pass while octets are still unread.
                        let after = &body[at + "r.expect_end()?;".len()..];
                        // "&mut r" has to be the reader itself, not a name
                        // that merely starts with it such as "&mut rng".
                        let reads_again = after.contains("&mut r)")
                            || after.contains("&mut r,")
                            || after.contains("&mut r ");
                        if reads_again {
                            problems.push(format!("{file}::{name} checks too early"));
                        }
                    }
                }
            }
        }
        assert!(problems.is_empty(), "{problems:#?}");
    }
}
