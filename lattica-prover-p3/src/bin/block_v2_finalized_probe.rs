//! Separately registered six-key mixed-root finalizer research driver.
const FINALIZER: bool = true;
const PAIRED: bool = false;
#[path = "typed_common/driver.rs"]
mod driver;
fn main() {
    driver::main();
}
