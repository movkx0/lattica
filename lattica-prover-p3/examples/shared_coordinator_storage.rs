//! Production-layout probe for the shared coordinator minimum. No proving or
//! GPU initialization; the CLI driver supplies its concrete report layouts.

#[cfg(all(target_os = "linux", feature = "block-v2", feature = "stream"))]
const FINALIZER: bool = true;
#[cfg(all(target_os = "linux", feature = "block-v2", feature = "stream"))]
const PAIRED: bool = true;
#[cfg(all(target_os = "linux", feature = "block-v2", feature = "stream"))]
#[path = "../src/bin/typed_common/driver.rs"]
mod driver;

#[cfg(all(target_os = "linux", feature = "block-v2", feature = "stream"))]
fn main() {
    driver::coordinator_storage_probe().unwrap();
}

#[cfg(not(all(target_os = "linux", feature = "block-v2", feature = "stream")))]
fn main() {
    eprintln!("shared_coordinator_storage requires Linux with block-v2 and stream");
    std::process::exit(2);
}
