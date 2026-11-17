use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use myssh_protocol::{
    FileBeginPayload, FileChunkPayload, FileDirection, FileEndPayload, FILE_CHUNK_SIZE,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically move a temporary file into place without replacing an
/// existing destination. Supported on Linux and Android.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn publish_noclobber(temp: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let temp = CString::new(temp.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid temporary path"))?;

    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid target path"))?;

    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            temp.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn publish_noclobber(_temp: &Path, _target: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Atomic no-clobber publication is not supported on this platform",
    ))
}

/// Host-side file storage configuration.
///
/// Files are confined to the canonicalized root directory.
/// Existing files are never overwritten.
#[derive(Debug, Clone)]
pub struct HostFileStore {
    root: PathBuf,
    max_file_size: u64,
}

/// A validated, read-only file handle prepared for download.
pub struct DownloadSource {
    pub file: File,
    pub file_size: u64,
    pub remote_path: String,
}

impl HostFileStore {
    pub fn new(root: impl AsRef<Path>, max_file_size: u64) -> io::Result<Self> {
        if max_file_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Maximum file size must be non-zero",
            ));
        }

        let root = fs::canonicalize(root)?;

        if !fs::metadata(&root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "File transfer root must be a directory",
            ));
        }

        Ok(Self {
            root,
            max_file_size,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn max_file_size(&self) -> u64 {
        self.max_file_size
    }

    /// Open an existing regular file for download.
    pub fn open_download(&self, remote_path: &str) -> io::Result<DownloadSource> {
        FileBeginPayload::validate_path(remote_path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid remote file path"))?;

        let relative = Path::new(remote_path);
        let mut components = relative.components().peekable();
        let mut current = self.root.clone();

        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid path component",
                ));
            };

            current.push(name);
            let metadata = fs::symlink_metadata(&current)?;

            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Download path contains a symlink",
                ));
            }

            if components.peek().is_some() {
                if !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        "Download parent component is not a directory",
                    ));
                }
            } else if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Download target is not a regular file",
                ));
            }
        }

        let file = File::open(&current)?;
        let opened_metadata = file.metadata()?;

        if !opened_metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Download target is not a regular file",
            ));
        }

        let file_size = opened_metadata.len();
        if file_size > self.max_file_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "File exceeds configured maximum size",
            ));
        }

        Ok(DownloadSource {
            file,
            file_size,
            remote_path: remote_path.to_owned(),
        })
    }

    /// Resolve an existing parent directory without following symlinks.
    fn resolve_upload_target(&self, remote_path: &str) -> io::Result<PathBuf> {
        FileBeginPayload::validate_path(remote_path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid remote file path"))?;

        let relative = Path::new(remote_path);

        // Require normal relative components only.
        for component in relative.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid path component",
                ));
            }
        }

        let mut components = relative.components().peekable();
        let mut parent = self.root.clone();

        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid path component",
                ));
            };

            let candidate = parent.join(name);

            if components.peek().is_some() {
                let metadata = fs::symlink_metadata(&candidate)?;

                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Parent path contains a symlink or non-directory",
                    ));
                }

                parent = candidate;
            } else {
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "Target file is a symlink",
                            ));
                        }

                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "Target file already exists",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(candidate);
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Remote path does not name a file",
        ))
    }

    pub fn begin_upload(&self, begin: &FileBeginPayload) -> io::Result<UploadTransaction> {
        if begin.direction != FileDirection::Upload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected an upload request",
            ));
        }

        if begin.file_size > self.max_file_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "File exceeds configured maximum size",
            ));
        }

        let target_path = self.resolve_upload_target(&begin.remote_path)?;

        let parent = target_path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Target has no parent"))?;

        // Temporary file is created beside the destination so the final
        // hard-link commit remains on the same filesystem.
        let (temp_path, file) = create_temp_file(parent)?;

        Ok(UploadTransaction {
            file: Some(file),
            temp_path,
            target_path,
            expected_size: begin.file_size,
            received_size: 0,
            next_chunk_index: 0,
            hasher: Sha256::new(),
            committed: false,
        })
    }
}

fn create_temp_file(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..32 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(".myssh-upload-{}-{}.tmp", std::process::id(), counter);
        let path = parent.join(name);

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not allocate a temporary upload file",
    ))
}

/// An in-progress upload.
///
/// Dropping this value before commit removes its temporary file.
pub struct UploadTransaction {
    file: Option<File>,
    temp_path: PathBuf,
    target_path: PathBuf,
    expected_size: u64,
    received_size: u64,
    next_chunk_index: u64,
    hasher: Sha256,
    committed: bool,
}

impl UploadTransaction {
    pub fn received_size(&self) -> u64 {
        self.received_size
    }

    pub fn next_chunk_index(&self) -> u64 {
        self.next_chunk_index
    }

    pub fn write_chunk(&mut self, chunk: &FileChunkPayload) -> io::Result<()> {
        if chunk.chunk_index != self.next_chunk_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected file chunk index",
            ));
        }

        if chunk.data.is_empty() || chunk.data.len() > FILE_CHUNK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid file chunk size",
            ));
        }

        let chunk_size = u64::try_from(chunk.data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Chunk size overflow"))?;

        let new_size = self
            .received_size
            .checked_add(chunk_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "File size overflow"))?;

        if new_size > self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Received more bytes than declared",
            ));
        }

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Upload is already closed"))?;

        file.write_all(&chunk.data)?;
        self.hasher.update(&chunk.data);
        self.received_size = new_size;

        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Chunk index overflow"))?;

        Ok(())
    }

    /// Verify size, chunk count and SHA-256, then atomically publish the file
    /// without overwriting an existing destination.
    pub fn finish(mut self, end: &FileEndPayload) -> io::Result<PathBuf> {
        if self.received_size != self.expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Received file size does not match FileBegin",
            ));
        }

        if end.total_size != self.received_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileEnd total size mismatch",
            ));
        }

        if end.total_chunks != self.next_chunk_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileEnd chunk count mismatch",
            ));
        }

        let actual_hash: [u8; 32] = self.hasher.clone().finalize().into();

        if actual_hash != end.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File SHA-256 verification failed",
            ));
        }

        let file = self
            .file
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Upload is already closed"))?;

        file.sync_all()?;
        drop(file);

        // renameat2(RENAME_NOREPLACE) atomically publishes the file
        // without replacing a destination that already exists.
        publish_noclobber(&self.temp_path, &self.target_path)?;

        self.committed = true;

        if let Some(parent) = self.target_path.parent() {
            if let Ok(directory) = File::open(parent) {
                directory.sync_all()?;
            }
        }

        Ok(self.target_path.clone())
    }
}

impl Drop for UploadTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myssh_protocol::{FileDirection, FileEndPayload};

    fn test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "myssh-stage06-{}-{}-{}",
            name,
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));

        fs::create_dir_all(&path).unwrap();
        path
    }

    fn begin(path: &str, size: u64) -> FileBeginPayload {
        FileBeginPayload {
            direction: FileDirection::Upload,
            file_size: size,
            remote_path: path.to_owned(),
        }
    }

    fn end(data: &[u8], chunks: u64) -> FileEndPayload {
        FileEndPayload {
            total_chunks: chunks,
            total_size: data.len() as u64,
            sha256: Sha256::digest(data).into(),
        }
    }

    #[test]
    fn upload_commits_verified_file() {
        let root = test_root("commit");
        let store = HostFileStore::new(&root, 1024).unwrap();
        let data = b"MySSH file transfer test";

        let mut upload = store
            .begin_upload(&begin("report.txt", data.len() as u64))
            .unwrap();

        upload
            .write_chunk(&FileChunkPayload {
                chunk_index: 0,
                data: data.to_vec(),
            })
            .unwrap();

        let target = upload.finish(&end(data, 1)).unwrap();

        assert_eq!(fs::read(&target).unwrap(), data);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_supports_empty_file() {
        let root = test_root("empty");
        let store = HostFileStore::new(&root, 1024).unwrap();

        let upload = store.begin_upload(&begin("empty.txt", 0)).unwrap();
        let target = upload.finish(&end(b"", 0)).unwrap();

        assert_eq!(fs::metadata(target).unwrap().len(), 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_rejects_existing_destination() {
        let root = test_root("existing");
        fs::write(root.join("existing.txt"), b"original").unwrap();

        let store = HostFileStore::new(&root, 1024).unwrap();

        let result = store.begin_upload(&begin("existing.txt", 1));

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(root.join("existing.txt")).unwrap(), b"original");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_rejects_oversized_file() {
        let root = test_root("oversized");
        let store = HostFileStore::new(&root, 4).unwrap();

        let result = store.begin_upload(&begin("large.bin", 5));

        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_rejects_out_of_order_chunks() {
        let root = test_root("order");
        let store = HostFileStore::new(&root, 1024).unwrap();

        let mut upload = store.begin_upload(&begin("ordered.bin", 2)).unwrap();

        let result = upload.write_chunk(&FileChunkPayload {
            chunk_index: 1,
            data: b"ab".to_vec(),
        });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);

        drop(upload);
        assert!(!root.join("ordered.bin").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_rejects_hash_mismatch_and_cleans_temp_file() {
        let root = test_root("hash");
        let store = HostFileStore::new(&root, 1024).unwrap();

        let mut upload = store.begin_upload(&begin("bad.bin", 3)).unwrap();

        upload
            .write_chunk(&FileChunkPayload {
                chunk_index: 0,
                data: b"abc".to_vec(),
            })
            .unwrap();

        let mut invalid_end = end(b"abc", 1);
        invalid_end.sha256 = [0; 32];

        assert!(upload.finish(&invalid_end).is_err());
        assert!(!root.join("bad.bin").exists());

        let entries: Vec<_> = fs::read_dir(&root).unwrap().collect();
        assert!(entries.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_rejects_file_size_mismatch() {
        let root = test_root("size");
        let store = HostFileStore::new(&root, 1024).unwrap();

        let mut upload = store.begin_upload(&begin("size.bin", 4)).unwrap();

        upload
            .write_chunk(&FileChunkPayload {
                chunk_index: 0,
                data: b"abc".to_vec(),
            })
            .unwrap();

        assert!(upload.finish(&end(b"abc", 1)).is_err());
        assert!(!root.join("size.bin").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn download_opens_regular_file_and_reports_size() {
        let root = test_root("download-open");
        let expected = b"download source data";
        fs::write(root.join("source.txt"), expected).unwrap();
        let store = HostFileStore::new(&root, 1024).unwrap();

        let source = store.open_download("source.txt").unwrap();
        assert_eq!(source.file_size, expected.len() as u64);
        assert_eq!(source.remote_path, "source.txt");

        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn download_rejects_missing_file() {
        let root = test_root("download-missing");
        let store = HostFileStore::new(&root, 1024).unwrap();

        let result = store.open_download("missing.txt");
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn download_rejects_directory_target() {
        let root = test_root("download-directory");
        fs::create_dir(root.join("folder")).unwrap();
        let store = HostFileStore::new(&root, 1024).unwrap();

        let result = store.open_download("folder");
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn download_rejects_oversized_file() {
        let root = test_root("download-oversized");
        fs::write(root.join("large.bin"), b"12345").unwrap();
        let store = HostFileStore::new(&root, 4).unwrap();

        let result = store.open_download("large.bin");
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn download_rejects_symlink_target_and_parent() {
        let root = test_root("download-symlink");
        let outside = test_root("download-outside");
        fs::write(outside.join("secret.txt"), b"secret").unwrap();

        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("link-file")).unwrap();

        std::os::unix::fs::symlink(&outside, root.join("link-dir")).unwrap();

        let store = HostFileStore::new(&root, 1024).unwrap();

        assert!(store.open_download("link-file").is_err());
        assert!(store.open_download("link-dir/secret.txt").is_err());

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn upload_rejects_symlink_parent() {
        #[cfg(unix)]
        {
            let root = test_root("symlink");
            let outside = test_root("outside");

            std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

            let store = HostFileStore::new(&root, 1024).unwrap();
            let result = store.begin_upload(&begin("link/escape.txt", 1));

            assert!(result.is_err());
            assert!(!outside.join("escape.txt").exists());

            fs::remove_dir_all(root).unwrap();
            fs::remove_dir_all(outside).unwrap();
        }
    }
}
