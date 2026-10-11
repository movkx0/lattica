use super::ERROR;

pub(super) fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b).ok_or(ERROR)
}
pub(super) fn mul(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_mul(b).ok_or(ERROR)
}

#[derive(Clone, Copy, Default)]
pub(super) struct Ledger(pub(super) usize);
impl Ledger {
    pub(super) fn bytes(&mut self, bytes: usize) -> Result<(), &'static str> {
        self.0 = add(self.0, bytes)?;
        Ok(())
    }
    pub(super) fn exact<T>(&mut self, count: usize) -> Result<(), &'static str> {
        self.bytes(mul(count, core::mem::size_of::<T>())?)
    }
    // Pinned RawVec geometric growth, including all replaced buffers. The
    // minimum capacity is at most eight; final capacity is below 2*max(n, 8).
    pub(super) fn growing<T>(&mut self, count: usize) -> Result<(), &'static str> {
        if count == 0 {
            return Ok(());
        }
        self.exact::<T>(mul(4, count.max(8))?)
    }
    pub(super) fn repeat(&mut self, other: Self, count: usize) -> Result<(), &'static str> {
        self.bytes(mul(other.0, count)?)
    }
}
