//! Five-key mixed-root reference driver.
const FINALIZER: bool = false;
const PAIRED: bool = false;
#[path = "typed_common/driver.rs"]
mod driver;
fn main() {
    driver::main();
}
