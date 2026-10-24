//! Canonical research framing: fixed-width little-endian integers, explicit u32
//! lengths, no padding, and no trailing bytes. Public-body and full-transaction
//! encodings have distinct versioned magic values. This is not a network format.

use sha3::{Digest, Sha3_256};

use crate::transaction::bounded_len;
use crate::{
    Error, Input, Limits, Output, ProfileId, PublicTransaction, RingReference, Transaction,
};

const BODY_MAGIC: &[u8; 8] = b"LPQRCB01";
const TRANSACTION_MAGIC: &[u8; 8] = b"LPQRCT01";
const BODY_DOMAIN: &[u8] = b"lattica:pq-ringct-research:body-binding:v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"lattica:pq-ringct-research:transaction-id:v1\0";

fn add(size: &mut usize, amount: usize) -> Result<(), Error> {
    *size = size.checked_add(amount).ok_or(Error::LengthOverflow)?;
    Ok(())
}

fn body_len(body: &PublicTransaction, limits: &Limits) -> Result<usize, Error> {
    body.validate_structure(limits)?;
    let mut size = 8 + 32 + 2 + 2 + 32 + 8 + 4 + 4;
    for input in &body.inputs {
        add(&mut size, 32 + 4 + 4)?;
        add(
            &mut size,
            input
                .ring
                .members
                .len()
                .checked_mul(8)
                .ok_or(Error::LengthOverflow)?,
        )?;
        add(&mut size, input.serial.len())?;
    }
    for output in &body.outputs {
        add(&mut size, 4 + 4)?;
        add(&mut size, output.commitment.len())?;
        add(&mut size, output.encrypted_note.len())?;
    }
    if size > limits.max_body_bytes {
        return Err(Error::Oversize("body"));
    }
    u32::try_from(size).map_err(|_| Error::LengthOverflow)?;
    Ok(size)
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(len)
            .map_err(|_| Error::LengthOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(Error::LengthOverflow)?;
        let result = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(result)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn count(&mut self, max: usize, name: &'static str) -> Result<usize, Error> {
        let count = self.u32()? as usize;
        bounded_len(count, max, name)?;
        Ok(count)
    }

    fn bytes(&mut self, max: usize, name: &'static str) -> Result<&'a [u8], Error> {
        let count = self.count(max, name)?;
        self.take(count)
    }

    fn finish(self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

impl PublicTransaction {
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, Error> {
        let size = body_len(self, limits)?;
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(BODY_MAGIC);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.profile.scheme.to_le_bytes());
        out.extend_from_slice(&self.profile.version.to_le_bytes());
        out.extend_from_slice(&self.profile.parameters);
        out.extend_from_slice(&self.fee.to_le_bytes());
        put_len(&mut out, self.inputs.len())?;
        for input in &self.inputs {
            out.extend_from_slice(&input.ring.anchor);
            put_len(&mut out, input.ring.members.len())?;
            for member in &input.ring.members {
                out.extend_from_slice(&member.to_le_bytes());
            }
            put_bytes(&mut out, &input.serial)?;
        }
        put_len(&mut out, self.outputs.len())?;
        for output in &self.outputs {
            put_bytes(&mut out, &output.commitment)?;
            put_bytes(&mut out, &output.encrypted_note)?;
        }
        debug_assert_eq!(out.len(), size);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        if bytes.len() > limits.max_body_bytes {
            return Err(Error::Oversize("body"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != BODY_MAGIC {
            return Err(Error::InvalidMagic);
        }
        let chain_id = reader.fixed()?;
        let profile = ProfileId {
            scheme: reader.u16()?,
            version: reader.u16()?,
            parameters: reader.fixed()?,
        };
        let fee = reader.u64()?;
        let count = reader.count(limits.max_inputs, "inputs")?;
        // Do not reserve memory from attacker-controlled counts. Every append is
        // preceded by successfully reading the corresponding bounded input.
        let mut inputs = Vec::new();
        for _ in 0..count {
            let anchor = reader.fixed()?;
            let count = reader.count(limits.max_ring_members, "ring members")?;
            let packed = reader.take(count.checked_mul(8).ok_or(Error::LengthOverflow)?)?;
            let members = packed
                .chunks_exact(8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk")))
                .collect();
            let serial = reader.bytes(limits.max_serial_bytes, "serial")?.to_vec();
            inputs.push(Input {
                ring: RingReference { anchor, members },
                serial,
            });
        }
        let count = reader.count(limits.max_outputs, "outputs")?;
        let mut outputs = Vec::new();
        for _ in 0..count {
            let commitment = reader
                .bytes(limits.max_commitment_bytes, "commitment")?
                .to_vec();
            let encrypted_note = reader
                .bytes(limits.max_encrypted_note_bytes, "encrypted note")?
                .to_vec();
            outputs.push(Output {
                commitment,
                encrypted_note,
            });
        }
        reader.finish()?;
        let body = Self {
            chain_id,
            profile,
            fee,
            inputs,
            outputs,
        };
        body.validate_structure(limits)?;
        Ok(body)
    }

    /// SHA3-256 of domain plus the canonical public body, including chain,
    /// profile, fee, ring anchors/members, serials, outputs, and encryption bytes.
    /// A scheme must incorporate this binding into its own proven statement or
    /// transcript; merely calculating or transmitting it confers no security.
    pub fn binding(&self, limits: &Limits) -> Result<[u8; 32], Error> {
        let mut hash = Sha3_256::new();
        hash.update(BODY_DOMAIN);
        hash.update(self.encode(limits)?);
        Ok(hash.finalize().into())
    }
}

impl Transaction {
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, Error> {
        bounded_len(self.proof.len(), limits.max_proof_bytes, "proof")?;
        let body_size = body_len(&self.body, limits)?;
        let mut size = 8 + 4 + 4;
        add(&mut size, body_size)?;
        add(&mut size, self.proof.len())?;
        if size > limits.max_transaction_bytes {
            return Err(Error::Oversize("transaction"));
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(TRANSACTION_MAGIC);
        put_bytes(&mut out, &self.body.encode(limits)?)?;
        put_bytes(&mut out, &self.proof)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        if bytes.len() > limits.max_transaction_bytes {
            return Err(Error::Oversize("transaction"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != TRANSACTION_MAGIC {
            return Err(Error::InvalidMagic);
        }
        let body_bytes = reader.bytes(limits.max_body_bytes, "body")?;
        let proof = reader.bytes(limits.max_proof_bytes, "proof")?;
        reader.finish()?;
        let body = PublicTransaction::decode(body_bytes, limits)?;
        Ok(Self {
            body,
            proof: proof.to_vec(),
        })
    }

    /// Identifier for these exact encoded bytes, distinct from the public body
    /// binding. It changes when randomized proof bytes change.
    pub fn id(&self, limits: &Limits) -> Result<[u8; 32], Error> {
        let mut hash = Sha3_256::new();
        hash.update(TRANSACTION_DOMAIN);
        hash.update(self.encode(limits)?);
        Ok(hash.finalize().into())
    }
}
