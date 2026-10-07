//! Separate twelve-key research driver for ordered typed wallet pairs.
const FINALIZER: bool = true;
const PAIRED: bool = true;
#[path = "typed_common/driver.rs"]
mod driver;
fn main() {
    driver::main();
}
