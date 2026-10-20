use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use rand::RngCore;

pub fn write(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut rnd = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let tmp_path = dir.join(format!(".sitegate-{}", hex::encode(rnd)));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp_path)?;
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}
