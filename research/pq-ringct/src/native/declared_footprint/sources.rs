//! Frozen declaration inventory for the reviewed native n10 census.
//! Updating native source invalidates the census until it is re-reviewed.
use sha3::{Digest, Sha3_256};
const SOURCES: &[(&[u8], [u8; 32])] = &[
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/declared_footprint.h")), [33, 161, 38, 125, 211, 77, 245, 132, 234, 236, 89, 55, 22, 180, 191, 58, 139, 186, 137, 134, 136, 178, 19, 103, 181, 47, 156, 140, 139, 164, 98, 182]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/declared_footprint.inc")), [105, 160, 184, 66, 102, 74, 82, 111, 88, 138, 103, 78, 102, 134, 218, 71, 84, 169, 70, 89, 192, 189, 226, 118, 151, 196, 180, 206, 106, 53, 67, 134]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/lattica_guard.h")), [97, 204, 140, 52, 245, 214, 113, 203, 161, 92, 101, 128, 188, 127, 105, 250, 58, 94, 92, 194, 49, 223, 156, 198, 178, 221, 228, 76, 155, 67, 154, 38]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/matrict.c")), [216, 156, 72, 180, 34, 153, 89, 0, 135, 203, 54, 194, 55, 222, 41, 67, 45, 200, 26, 60, 57, 4, 250, 85, 206, 58, 228, 206, 40, 237, 107, 68]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/private_spend_fixture.inc")), [208, 202, 95, 154, 120, 91, 145, 46, 151, 0, 223, 214, 90, 248, 54, 174, 113, 138, 226, 122, 234, 29, 41, 168, 243, 191, 85, 11, 237, 152, 237, 217]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/private_spend_oracle.h")), [254, 233, 80, 6, 228, 227, 129, 172, 146, 85, 186, 169, 8, 145, 197, 255, 109, 212, 80, 25, 83, 169, 207, 182, 58, 67, 223, 208, 53, 248, 124, 155]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/comp.h")), [8, 170, 201, 158, 40, 26, 54, 199, 111, 180, 210, 171, 78, 119, 107, 161, 82, 73, 221, 19, 251, 149, 174, 199, 75, 112, 33, 91, 20, 17, 82, 102]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/fastrandombytes.c")), [242, 116, 17, 134, 101, 183, 81, 106, 0, 60, 183, 142, 148, 121, 54, 166, 125, 90, 110, 115, 189, 16, 20, 251, 230, 164, 219, 24, 108, 245, 14, 229]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/fastrandombytes.h")), [8, 28, 183, 206, 124, 225, 232, 108, 254, 94, 101, 212, 139, 232, 147, 123, 239, 247, 1, 33, 124, 100, 107, 16, 222, 13, 164, 239, 249, 193, 238, 246]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/gaussian_avx.c")), [43, 177, 90, 233, 136, 136, 69, 202, 165, 253, 242, 21, 95, 190, 22, 187, 141, 38, 233, 122, 67, 225, 23, 68, 47, 102, 49, 243, 123, 78, 242, 199]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/gaussian_avx.h")), [167, 51, 86, 243, 246, 137, 152, 148, 10, 156, 117, 147, 55, 91, 16, 217, 76, 104, 120, 240, 201, 222, 75, 14, 169, 231, 72, 185, 209, 49, 87, 28]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/hash.c")), [241, 72, 33, 206, 14, 225, 220, 245, 150, 101, 126, 239, 15, 30, 168, 179, 170, 31, 57, 95, 198, 157, 144, 66, 154, 239, 65, 240, 103, 176, 211, 157]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/hash.h")), [14, 172, 22, 182, 179, 197, 63, 30, 32, 247, 148, 21, 27, 121, 97, 3, 9, 4, 109, 154, 202, 80, 224, 166, 172, 239, 141, 216, 166, 189, 154, 163]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/keygen.c")), [164, 19, 106, 12, 36, 242, 23, 189, 170, 136, 138, 210, 223, 171, 53, 204, 16, 126, 113, 39, 245, 205, 194, 91, 140, 219, 133, 249, 205, 207, 11, 126]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/keygen.h")), [15, 2, 219, 191, 243, 186, 233, 183, 134, 209, 74, 28, 58, 80, 243, 220, 249, 225, 51, 227, 56, 182, 106, 92, 73, 3, 126, 192, 95, 113, 215, 172]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/littleendian.h")), [77, 72, 196, 16, 17, 162, 130, 212, 161, 13, 179, 125, 81, 175, 22, 177, 175, 189, 178, 91, 57, 80, 43, 29, 230, 207, 25, 212, 151, 220, 117, 241]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/mint.c")), [28, 40, 191, 129, 16, 108, 45, 231, 98, 247, 163, 189, 116, 114, 161, 153, 2, 161, 119, 31, 138, 201, 0, 196, 188, 209, 43, 231, 92, 192, 183, 12]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/mint.h")), [103, 193, 224, 122, 43, 27, 245, 3, 88, 204, 174, 102, 46, 53, 111, 43, 120, 139, 240, 171, 37, 139, 89, 67, 147, 150, 3, 132, 139, 117, 201, 55]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/param.h")), [0, 111, 206, 109, 110, 45, 145, 26, 49, 3, 55, 243, 225, 188, 101, 228, 57, 218, 250, 26, 25, 150, 208, 114, 179, 43, 251, 167, 32, 248, 242, 156]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_mult.c")), [41, 137, 20, 183, 248, 8, 97, 69, 150, 252, 125, 18, 177, 72, 2, 183, 101, 82, 219, 168, 163, 134, 75, 250, 247, 104, 173, 5, 157, 119, 187, 150]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_mult.h")), [179, 28, 151, 192, 169, 220, 79, 156, 42, 224, 38, 169, 57, 79, 187, 22, 31, 56, 180, 222, 93, 93, 143, 160, 145, 128, 222, 165, 90, 7, 81, 107]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_param.h")), [241, 145, 86, 8, 208, 180, 3, 228, 103, 199, 168, 191, 36, 243, 176, 26, 177, 41, 153, 87, 37, 187, 7, 140, 4, 184, 28, 84, 174, 108, 231, 20]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_q.c")), [229, 151, 168, 213, 166, 175, 204, 7, 201, 170, 178, 241, 183, 73, 181, 9, 57, 71, 31, 109, 143, 84, 110, 77, 30, 255, 4, 97, 163, 254, 108, 220]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_q.h")), [30, 3, 197, 0, 226, 28, 141, 119, 103, 139, 232, 23, 217, 103, 175, 246, 182, 216, 9, 57, 87, 214, 97, 109, 19, 64, 174, 111, 152, 251, 220, 83]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/poly_red.h")), [94, 194, 172, 170, 248, 18, 159, 233, 49, 152, 198, 184, 52, 20, 34, 45, 12, 130, 185, 201, 81, 10, 138, 18, 35, 71, 84, 93, 17, 94, 47, 62]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/sammat.c")), [171, 132, 250, 169, 198, 134, 16, 240, 38, 73, 65, 219, 197, 149, 159, 106, 197, 207, 213, 144, 5, 196, 224, 69, 32, 232, 2, 54, 252, 231, 173, 31]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/sammat.h")), [196, 65, 56, 178, 107, 204, 144, 140, 118, 102, 51, 74, 231, 133, 195, 173, 15, 212, 100, 78, 117, 107, 46, 210, 68, 209, 217, 125, 211, 51, 51, 23]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/sampleb.c")), [0, 227, 96, 18, 31, 192, 85, 205, 199, 99, 68, 75, 236, 238, 178, 132, 171, 20, 78, 138, 155, 220, 146, 129, 76, 153, 53, 200, 105, 135, 125, 92]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/sampleb.h")), [64, 194, 227, 247, 197, 203, 232, 152, 198, 58, 71, 178, 123, 129, 1, 201, 168, 23, 55, 199, 130, 78, 120, 195, 244, 64, 183, 176, 254, 8, 202, 153]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/setup.c")), [253, 32, 164, 228, 147, 7, 116, 0, 221, 43, 111, 10, 174, 209, 143, 163, 73, 5, 242, 122, 54, 59, 69, 167, 118, 40, 61, 92, 133, 169, 124, 117]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/setup.h")), [187, 161, 225, 156, 125, 242, 230, 45, 120, 71, 33, 158, 229, 176, 26, 146, 152, 149, 135, 52, 178, 150, 81, 207, 239, 68, 199, 151, 100, 96, 157, 215]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/spend.c")), [70, 7, 206, 190, 177, 208, 133, 248, 184, 177, 96, 141, 133, 174, 10, 224, 184, 67, 68, 35, 103, 224, 222, 26, 8, 158, 137, 96, 67, 254, 1, 6]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/spend.h")), [64, 76, 100, 29, 73, 57, 146, 1, 185, 168, 216, 31, 163, 122, 62, 185, 223, 91, 229, 54, 165, 13, 49, 102, 93, 183, 14, 10, 108, 218, 249, 254]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/verify.c")), [79, 76, 253, 54, 248, 133, 227, 181, 140, 143, 233, 191, 148, 133, 164, 107, 150, 149, 41, 135, 251, 192, 182, 17, 27, 186, 8, 205, 89, 39, 53, 32]),
    (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/vendor/matrict-plus/n10/verify.h")), [162, 116, 173, 163, 135, 35, 72, 32, 231, 245, 179, 95, 92, 235, 191, 211, 173, 146, 43, 10, 102, 89, 44, 201, 114, 223, 45, 122, 203, 78, 118, 151]),
];
pub(super) fn matches_reviewed_sources() -> bool {
    SOURCES.iter().all(|(source, expected)| {
        let actual: [u8; 32] = Sha3_256::digest(source).into();
        actual == *expected
    })
}

pub(super) fn retained_source_bytes() -> Result<u64, &'static str> {
    let headers = core::mem::size_of_val(SOURCES)
        .checked_add(core::mem::size_of_val(&SOURCES))
        .ok_or("native source-pin storage overflow")?;
    let bytes = SOURCES.iter().try_fold(headers, |total, (source, _)| {
        total.checked_add(source.len()).ok_or("native source-pin storage overflow")
    })?;
    u64::try_from(bytes).map_err(|_| "native source-pin storage width")
}
