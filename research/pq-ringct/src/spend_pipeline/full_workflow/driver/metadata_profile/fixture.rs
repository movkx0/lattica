//! Public, independently verified N3 inputs. No private keys or capabilities.
use crate::spend_pipeline::full_workflow::InitialNativeSource;
use crate::{
    execution::retained_resources::{
        Bytes, Category, Ledger, Requirements, Reservation, WorkerAllowance,
    },
    native::declared_footprint::DeclaredNativeFootprint,
    native_packet::{PROOF_BYTES, STATEMENT_BYTES},
    rust_verify::{committed_backend::source_graph::InitialSourceFootprint, Proof, Statement},
};
use sha3::{Digest, Sha3_256};
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
};

pub(super) const MAGIC: &[u8; 17] = b"RINGCT-N3-FIX-v1\0";
pub(super) const FRAME_BYTES: usize = 16 << 10;

pub(crate) fn capture(sources: &[InitialNativeSource<'_>]) -> io::Result<()> {
    let Some(path) = std::env::var_os("LATTICA_RINGCT_METADATA_FIXTURE_OUT") else {
        return Ok(());
    };
    if !super::active() || sources.len() != 3 {
        return Err(io::Error::other(
            "fixture capture requires N3 metadata profile",
        ));
    }
    let mut out = OpenOptions::new().write(true).create_new(true).open(path)?;
    write(&mut out, &sources)?;
    out.sync_all()?;
    eprintln!("RINGCT_METADATA_FIXTURE_CAPTURED transactions=3");
    Ok(())
}

fn write(out: &mut impl Write, sources: &[InitialNativeSource<'_>]) -> io::Result<()> {
    if sources.len() != 3 {
        return Err(io::Error::other("fixture requires three inputs"));
    }
    let mut digest = Sha3_256::new();
    let mut part = |bytes: &[u8]| -> io::Result<()> {
        digest.update(bytes);
        out.write_all(bytes)
    };
    part(MAGIC)?;
    for source in sources {
        part(&source.setup_seed())?;
        part(source.context())?;
        part(source.statement_bytes())?;
        part(source.proof_bytes())?;
    }
    out.write_all(&digest.finalize())
}

struct Input {
    statement_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    statement: Statement,
    proof: Proof,
    setup_seed: [u8; 32],
    context: [u8; 32],
}
impl Input {
    fn view(&self) -> io::Result<InitialNativeSource<'_>> {
        InitialNativeSource::new(
            self.setup_seed,
            self.context,
            &self.statement_bytes,
            &self.proof_bytes,
            &self.statement,
            &self.proof,
        )
        .map_err(io::Error::other)
    }
}
pub(super) struct Inputs {
    inputs: [Input; 3],
    pub(super) digest: [u8; 32],
    // Actual payloads precede their original backing in destruction order.
    _original: Reservation,
    ledger: Ledger,
}
fn bad() -> io::Error {
    io::Error::other("invalid or unverified N3 metadata fixture")
}
fn claim(category: Category, host: u64) -> Requirements {
    Requirements::single(category, Bytes { host, device: 0 })
}
impl Inputs {
    pub(super) fn read(path: &std::path::Path) -> io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let expected = MAGIC.len() + 3 * (64 + STATEMENT_BYTES + PROOF_BYTES) + 32;
        if file.metadata()?.len() != expected as u64 {
            return Err(bad());
        }
        let footprint = InitialSourceFootprint::fixed().map_err(io::Error::other)?;
        let native = DeclaredNativeFootprint::reviewed().map_err(io::Error::other)?;
        let ledger = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 8 << 30,
        });
        let retained = 3 * (STATEMENT_BYTES + PROOF_BYTES + footprint.decoded_bytes())
            + 8 * core::mem::size_of::<Self>()
            + FRAME_BYTES;
        let mut original_requirements = claim(Category::NativeProof, retained as u64);
        original_requirements
            .add(
                Category::RegisteredMetadata,
                Bytes {
                    host: native.shared_static_bytes(),
                    device: 0,
                },
            )
            .map_err(|_| bad())?;
        let original = ledger
            .admit_phase(original_requirements)
            .map_err(|_| bad())?;
        let scratch = ledger
            .admit_phase(claim(
                Category::IndependentVerifier,
                native.verifier_bytes()
                    + footprint.decode_temporary_bytes() as u64
                    + 4 * InitialNativeSource::inspection_frame_bytes() as u64
                    + FRAME_BYTES as u64,
            ))
            .map_err(|_| bad())?;
        let mut digest = Sha3_256::new();
        let mut part = |bytes: &mut [u8]| -> io::Result<()> {
            file.read_exact(bytes)?;
            digest.update(bytes);
            Ok(())
        };
        let mut magic = [0u8; 17];
        part(&mut magic)?;
        if &magic != MAGIC {
            return Err(bad());
        }
        let mut inputs: [Option<Input>; 3] = core::array::from_fn(|_| None);
        for input in &mut inputs {
            let mut setup_seed = [0; 32];
            let mut context = [0; 32];
            part(&mut setup_seed)?;
            part(&mut context)?;
            if setup_seed != [17; 32] || context != [34; 32] {
                return Err(bad());
            }
            let mut statement_bytes = vec![0; STATEMENT_BYTES];
            let mut proof_bytes = vec![0; PROOF_BYTES];
            part(&mut statement_bytes)?;
            part(&mut proof_bytes)?;
            if statement_bytes.capacity() != STATEMENT_BYTES
                || proof_bytes.capacity() != PROOF_BYTES
                || !crate::native::verify(&context, &statement_bytes, &proof_bytes)
                    .map_err(|_| bad())?
            {
                return Err(bad());
            }
            let statement = Statement::decode(&statement_bytes).map_err(|_| bad())?;
            let proof = Proof::decode(&proof_bytes).map_err(|_| bad())?;
            let value = Input {
                statement_bytes,
                proof_bytes,
                statement,
                proof,
                setup_seed,
                context,
            };
            value.view()?;
            *input = Some(value);
        }
        let mut stored_digest = [0; 32];
        file.read_exact(&mut stored_digest)?;
        let calculated: [u8; 32] = digest.finalize().into();
        if stored_digest != calculated {
            return Err(bad());
        }
        let [Some(first), Some(second), Some(third)] = inputs else {
            return Err(bad());
        };
        drop(scratch);
        Ok(Self {
            inputs: [first, second, third],
            digest: calculated,
            _original: original,
            ledger,
        })
    }
    pub(super) fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub(super) fn views(&self) -> io::Result<[InitialNativeSource<'_>; 3]> {
        Ok([
            self.inputs[0].view()?,
            self.inputs[1].view()?,
            self.inputs[2].view()?,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_rejects_truncated_wrong_profile_and_unverified_inputs() {
        let path = std::env::temp_dir().join(format!(
            "ringct-metadata-fixture-refusal-{}.bin",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(MAGIC).unwrap();
        drop(file);
        assert!(Inputs::read(&path).is_err());
        let mut bytes = vec![0u8; MAGIC.len() + 3 * (64 + STATEMENT_BYTES + PROOF_BYTES) + 32];
        std::fs::write(&path, &bytes).unwrap();
        assert!(Inputs::read(&path).is_err());
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        std::fs::write(&path, &bytes).unwrap();
        assert!(Inputs::read(&path).is_err());
        for index in 0..3 {
            let start = MAGIC.len() + index * (64 + STATEMENT_BYTES + PROOF_BYTES);
            bytes[start..start + 32].fill(17);
            bytes[start + 32..start + 64].fill(34);
        }
        // A correct container digest cannot authenticate a fabricated proof.
        let end = bytes.len() - 32;
        let digest = Sha3_256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
        std::fs::write(&path, &bytes).unwrap();
        assert!(Inputs::read(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
