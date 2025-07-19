use std::{fs, io};
use std::path::Path;
use std::string::ToString;

pub fn get_files_and_subdirs(dir: &Path, files: &mut Vec<String>, prefix: Option<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path  = entry.path();
        if path.is_file() {
            let name = prefix.clone().unwrap_or_default() + path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            files.push(name);
        } else if path.is_dir() {
            // recursive call
            get_files_and_subdirs(&path, files, Some(prefix.clone().unwrap_or_default() + &path.file_name().unwrap().to_string_lossy() + "/"))?;
        }
    }
    Ok(())
}