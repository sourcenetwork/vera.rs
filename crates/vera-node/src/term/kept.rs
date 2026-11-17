//! The finalization certificates a device keeps while it rebuilds marshal's
//! archive of them: each as its height, its length and its bytes.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read as _, Write as _},
    path::{Path, PathBuf},
};

use super::TermRefusal;

const FILE: &str = "kept-finalizations";
const PENDING: &str = "kept-finalizations.pending";
/// No certificate is larger than a block may be.
const LIMIT: usize = vera_domain::MAX_BLOCK_BYTES;

pub(crate) fn path(directory: &Path) -> PathBuf {
    directory.join(FILE)
}

/// Whether `directory` holds a complete file.
pub(crate) fn stored(directory: &Path) -> bool {
    path(directory).is_file()
}

fn failed(directory: &Path) -> impl Fn(std::io::Error) -> TermRefusal {
    let path = path(directory);
    move |source| TermRefusal::Io {
        path: path.clone(),
        source,
    }
}

pub(crate) struct Writer<'a> {
    directory: &'a Path,
    file: BufWriter<File>,
}

impl<'a> Writer<'a> {
    pub(crate) fn create(directory: &'a Path) -> Result<Self, TermRefusal> {
        let file = File::create(directory.join(PENDING)).map_err(failed(directory))?;
        Ok(Self {
            directory,
            file: BufWriter::new(file),
        })
    }

    pub(crate) fn push(&mut self, height: u64, certificate: &[u8]) -> Result<(), TermRefusal> {
        let length = u32::try_from(certificate.len()).map_err(|_| TermRefusal::Record {
            path: path(self.directory),
            reason: "oversized finalization certificate".into(),
        })?;
        self.file
            .write_all(&height.to_be_bytes())
            .and_then(|()| self.file.write_all(&length.to_be_bytes()))
            .and_then(|()| self.file.write_all(certificate))
            .map_err(failed(self.directory))
    }

    /// Make the file durable under its name.
    pub(crate) fn finish(self) -> Result<(), TermRefusal> {
        let directory = self.directory;
        let publish = || {
            let file = self.file.into_inner().map_err(|error| error.into_error())?;
            file.sync_all()?;
            std::fs::rename(directory.join(PENDING), path(directory))?;
            File::open(directory)?.sync_all()
        };
        publish().map_err(failed(directory))
    }
}

/// The certificates in the file, in the order they were written.
pub(crate) fn read(
    directory: &Path,
) -> Result<impl Iterator<Item = Result<(u64, Vec<u8>), TermRefusal>>, TermRefusal> {
    let mut file = BufReader::new(File::open(path(directory)).map_err(failed(directory))?);
    let failed = failed(directory);
    let truncated = path(directory);
    Ok(std::iter::from_fn(move || {
        let mut height = [0u8; 8];
        match file.read(&mut height[..1]) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(error) => return Some(Err(failed(error))),
        }
        let mut length = [0u8; 4];
        let entry = file
            .read_exact(&mut height[1..])
            .and_then(|()| file.read_exact(&mut length))
            .map_err(&failed)
            .and_then(|()| {
                let length = u32::from_be_bytes(length) as usize;
                if length > LIMIT {
                    return Err(TermRefusal::Record {
                        path: truncated.clone(),
                        reason: "oversized finalization certificate".into(),
                    });
                }
                let mut certificate = vec![0u8; length];
                file.read_exact(&mut certificate).map_err(&failed)?;
                Ok((u64::from_be_bytes(height), certificate))
            });
        Some(entry)
    }))
}

pub(crate) fn remove(directory: &Path) -> Result<(), TermRefusal> {
    let remove = || {
        std::fs::remove_file(path(directory))?;
        File::open(directory)?.sync_all()
    };
    remove().map_err(failed(directory))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_are_read_back_as_written_once_the_file_is_finished() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = Writer::create(directory.path()).unwrap();
        writer.push(7, b"seven").unwrap();
        writer.push(9, b"").unwrap();
        assert!(!stored(directory.path()));
        writer.finish().unwrap();
        assert!(stored(directory.path()));
        let entries: Vec<_> = read(directory.path())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(entries, [(7, b"seven".to_vec()), (9, Vec::new())]);
        remove(directory.path()).unwrap();
        assert!(!stored(directory.path()));
    }

    #[test]
    fn a_file_cut_short_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = Writer::create(directory.path()).unwrap();
        writer.push(7, b"seven").unwrap();
        writer.finish().unwrap();
        let bytes = std::fs::read(path(directory.path())).unwrap();
        std::fs::write(path(directory.path()), &bytes[..bytes.len() - 2]).unwrap();
        let entries: Vec<_> = read(directory.path()).unwrap().collect();
        assert!(matches!(entries.as_slice(), [Err(TermRefusal::Io { .. })]));
    }
}
