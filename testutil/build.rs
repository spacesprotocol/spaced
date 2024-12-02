use std::env;
use std::fs;
use std::path::Path;
use std::io;

fn main() -> io::Result<()> {
    let zip_path = Path::new("testdata/regtest.zip");
    if !zip_path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no regtest testdata found in testdata/regtest.zip"));
    }
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).join("regtest_unpacked");

    if target_dir.exists() {
        return Ok(());
    }

    fs::create_dir_all(&target_dir)?;

    // Unpack the ZIP file
    let zip_file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(zip_file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = target_dir.join(file.name());

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }
    println!("cargo:rerun-if-changed=testdata/regtest.zip");
    Ok(())
}
