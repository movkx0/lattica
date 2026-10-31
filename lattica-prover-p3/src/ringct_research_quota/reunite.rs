//! Reunite original category-preserving claims without another admission.
use super::*;

fn combined(left: Requirements, right: Requirements) -> Result<Requirements, Error> {
    let mut result = left;
    for category in Category::ALL {
        result.add(category, right.get(category))?;
    }
    Ok(result)
}

impl Reservation {
    /// Consume two original claims from the same ledger into one owner. Every
    /// category remains unchanged, and current/peak ledger counters do not
    /// change. This is ownership transfer, not permission for another phase.
    ///
    /// Refusal returns both original non-Clone tokens intact. All arithmetic
    /// and ledger identity checks precede either token's mutation. Successful
    /// destruction of the empty donor releases no bytes or category charge.
    pub fn reunite(mut self, mut other: Self) -> Result<Self, (Error, Self, Self)> {
        if !Rc::ptr_eq(&self.ledger, &other.ledger) {
            return Err((Error::DifferentLedger, self, other));
        }
        let total = match combined(self.reserved, other.reserved) {
            Ok(total) => total,
            Err(error) => return Err((error, self, other)),
        };
        self.reserved = total;
        other.reserved = Requirements::default();
        drop(other);
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
