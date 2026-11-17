use std::collections::{HashMap, HashSet};
use std::io;

use myssh_core::{SessionKind, SessionManager};
use myssh_protocol::{
    FileBeginPayload, FileChunkPayload, FileDirection, FileEndPayload, FileErrorCode,
    FileRequestPayload, FileResponsePayload, FileResponseStatus, Frame, MessageKind,
    SessionOpenPayload, SessionOpenStatus, SessionOpenedPayload, SessionType,
};

use crate::file_transfer::{DownloadSource, HostFileStore, UploadTransaction};

/// Manages file-transfer state for one authenticated connection.
///
/// Session IDs are allocated by the shared Core SessionManager.
/// This manager owns only file-transfer transactions.
pub struct FileTransferSessionManager {
    store: HostFileStore,
    uploads: HashMap<u128, UploadTransaction>,
    active_downloads: HashSet<u128>,
    active_sessions: HashSet<u128>,
}

impl FileTransferSessionManager {
    pub fn new(store: HostFileStore) -> Self {
        Self {
            store,
            uploads: HashMap::new(),
            active_downloads: HashSet::new(),
            active_sessions: HashSet::new(),
        }
    }

    /// Accept a FileTransfer SessionOpen request.
    pub fn accept_open_request(
        &mut self,
        core_sessions: &mut SessionManager,
        request: &Frame,
    ) -> io::Result<Frame> {
        if request.header.kind != MessageKind::SessionOpen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected SessionOpen frame",
            ));
        }

        if request.header.session_id != 0 || request.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SessionOpen header",
            ));
        }

        let payload = SessionOpenPayload::decode(&request.payload)?;

        if payload.session_type != SessionType::FileTransfer {
            return Self::build_open_response(
                SessionOpenStatus::Unsupported,
                0,
                request.header.request_id,
            );
        }

        let session = match core_sessions.open(SessionKind::FileTransfer) {
            Ok(session) => session,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Self::build_open_response(
                    SessionOpenStatus::Rejected,
                    0,
                    request.header.request_id,
                );
            }
            Err(error) => return Err(error),
        };

        self.active_sessions.insert(session.id);

        match Self::build_open_response(
            SessionOpenStatus::Accepted,
            session.id,
            request.header.request_id,
        ) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.active_sessions.remove(&session.id);
                core_sessions.close(session.id);
                Err(error)
            }
        }
    }

    fn build_open_response(
        status: SessionOpenStatus,
        session_id: u128,
        request_id: u64,
    ) -> io::Result<Frame> {
        Frame::new(
            MessageKind::SessionOpened,
            session_id,
            request_id,
            SessionOpenedPayload { status }.encode(),
        )
    }

    fn validate_session(core_sessions: &SessionManager, session_id: u128) -> io::Result<()> {
        if session_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File transfer requires a non-zero session ID",
            ));
        }

        match core_sessions.get(session_id) {
            Some(session) if session.kind == SessionKind::FileTransfer => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Session is not a FileTransfer session",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Unknown FileTransfer session",
            )),
        }
    }

    fn build_file_response(
        status: FileResponseStatus,
        error_code: FileErrorCode,
        session_id: u128,
        request_id: u64,
    ) -> io::Result<Frame> {
        let payload = FileResponsePayload { status, error_code }.encode()?;

        Frame::new(MessageKind::FileResponse, session_id, request_id, payload)
    }

    fn map_file_error(error: &io::Error) -> FileErrorCode {
        match error.kind() {
            io::ErrorKind::NotFound => FileErrorCode::NotFound,
            io::ErrorKind::PermissionDenied => FileErrorCode::PermissionDenied,
            io::ErrorKind::AlreadyExists => FileErrorCode::AlreadyExists,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
                FileErrorCode::InvalidRequest
            }
            _ => FileErrorCode::Io,
        }
    }

    /// Begin an upload and create its temporary destination file.
    pub fn handle_begin(
        &mut self,
        core_sessions: &SessionManager,
        frame: &Frame,
    ) -> io::Result<Frame> {
        if frame.header.kind != MessageKind::FileBegin {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected FileBegin frame",
            ));
        }

        if frame.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileBegin requires a non-zero request ID",
            ));
        }

        Self::validate_session(core_sessions, frame.header.session_id)?;

        if self.uploads.contains_key(&frame.header.session_id)
            || self.active_downloads.contains(&frame.header.session_id)
        {
            return Self::build_file_response(
                FileResponseStatus::Rejected,
                FileErrorCode::InvalidRequest,
                frame.header.session_id,
                frame.header.request_id,
            );
        }

        let begin = match FileBeginPayload::decode(&frame.payload) {
            Ok(begin) if begin.direction == FileDirection::Upload => begin,
            Ok(_) => {
                return Self::build_file_response(
                    FileResponseStatus::Rejected,
                    FileErrorCode::InvalidRequest,
                    frame.header.session_id,
                    frame.header.request_id,
                );
            }
            Err(error) => {
                return Self::build_file_response(
                    FileResponseStatus::Rejected,
                    Self::map_file_error(&error),
                    frame.header.session_id,
                    frame.header.request_id,
                );
            }
        };

        match self.store.begin_upload(&begin) {
            Ok(upload) => {
                self.uploads.insert(frame.header.session_id, upload);

                Self::build_file_response(
                    FileResponseStatus::Ready,
                    FileErrorCode::None,
                    frame.header.session_id,
                    frame.header.request_id,
                )
            }
            Err(error) => Self::build_file_response(
                FileResponseStatus::Rejected,
                Self::map_file_error(&error),
                frame.header.session_id,
                frame.header.request_id,
            ),
        }
    }

    /// Receive one upload chunk.
    ///
    /// Any chunk error discards the transaction. Dropping UploadTransaction
    /// removes its uncommitted temporary file.
    pub fn handle_chunk(
        &mut self,
        core_sessions: &SessionManager,
        frame: &Frame,
    ) -> io::Result<()> {
        if frame.header.kind != MessageKind::FileChunk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected FileChunk frame",
            ));
        }

        if frame.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileChunk requires a non-zero request ID",
            ));
        }

        Self::validate_session(core_sessions, frame.header.session_id)?;

        let chunk = match FileChunkPayload::decode(&frame.payload) {
            Ok(chunk) => chunk,
            Err(error) => {
                self.uploads.remove(&frame.header.session_id);
                return Err(error);
            }
        };

        let result = match self.uploads.get_mut(&frame.header.session_id) {
            Some(upload) => upload.write_chunk(&chunk),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FileChunk received before FileBegin",
                ));
            }
        };

        if let Err(error) = result {
            self.uploads.remove(&frame.header.session_id);
            return Err(error);
        }

        Ok(())
    }

    /// Verify and commit an upload.
    pub fn handle_end(
        &mut self,
        core_sessions: &SessionManager,
        frame: &Frame,
    ) -> io::Result<Frame> {
        if frame.header.kind != MessageKind::FileEnd {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected FileEnd frame",
            ));
        }

        if frame.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileEnd requires a non-zero request ID",
            ));
        }

        Self::validate_session(core_sessions, frame.header.session_id)?;

        let end = match FileEndPayload::decode(&frame.payload) {
            Ok(end) => end,
            Err(error) => {
                self.uploads.remove(&frame.header.session_id);
                return Self::build_file_response(
                    FileResponseStatus::Failed,
                    Self::map_file_error(&error),
                    frame.header.session_id,
                    frame.header.request_id,
                );
            }
        };

        let Some(upload) = self.uploads.remove(&frame.header.session_id) else {
            return Self::build_file_response(
                FileResponseStatus::Failed,
                FileErrorCode::InvalidRequest,
                frame.header.session_id,
                frame.header.request_id,
            );
        };

        match upload.finish(&end) {
            Ok(_published_path) => Self::build_file_response(
                FileResponseStatus::Completed,
                FileErrorCode::None,
                frame.header.session_id,
                frame.header.request_id,
            ),
            Err(error) => Self::build_file_response(
                FileResponseStatus::Failed,
                if error.kind() == io::ErrorKind::InvalidData {
                    FileErrorCode::IntegrityMismatch
                } else {
                    Self::map_file_error(&error)
                },
                frame.header.session_id,
                frame.header.request_id,
            ),
        }
    }

    /// Accept a request to download one file from the Host.
    ///
    /// A successful request reserves the session until finish_download()
    /// or session cleanup. The returned DownloadSource owns the open file.
    pub fn handle_request(
        &mut self,
        core_sessions: &SessionManager,
        frame: &Frame,
    ) -> io::Result<(Frame, Option<DownloadSource>)> {
        if frame.header.kind != MessageKind::FileRequest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected FileRequest frame",
            ));
        }

        if frame.header.request_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FileRequest requires a non-zero request ID",
            ));
        }

        Self::validate_session(core_sessions, frame.header.session_id)?;

        let session_id = frame.header.session_id;
        let request_id = frame.header.request_id;

        if self.uploads.contains_key(&session_id) || self.active_downloads.contains(&session_id) {
            let response = Self::build_file_response(
                FileResponseStatus::Rejected,
                FileErrorCode::InvalidRequest,
                session_id,
                request_id,
            )?;

            return Ok((response, None));
        }

        let request = match FileRequestPayload::decode(&frame.payload) {
            Ok(request) => request,
            Err(error) => {
                let response = Self::build_file_response(
                    FileResponseStatus::Rejected,
                    Self::map_file_error(&error),
                    session_id,
                    request_id,
                )?;

                return Ok((response, None));
            }
        };

        match self.store.open_download(&request.remote_path) {
            Ok(source) => {
                self.active_downloads.insert(session_id);

                let response = Self::build_file_response(
                    FileResponseStatus::Ready,
                    FileErrorCode::None,
                    session_id,
                    request_id,
                )?;

                Ok((response, Some(source)))
            }
            Err(error) => {
                let response = Self::build_file_response(
                    FileResponseStatus::Rejected,
                    Self::map_file_error(&error),
                    session_id,
                    request_id,
                )?;

                Ok((response, None))
            }
        }
    }

    /// Release the session's active download reservation.
    pub fn finish_download(&mut self, session_id: u128) -> bool {
        self.active_downloads.remove(&session_id)
    }

    /// Close a FileTransfer session and discard any unfinished transfer.
    pub fn close(
        &mut self,
        core_sessions: &mut SessionManager,
        session_id: u128,
    ) -> io::Result<bool> {
        Self::validate_session(core_sessions, session_id)?;

        self.uploads.remove(&session_id);
        self.active_downloads.remove(&session_id);
        self.active_sessions.remove(&session_id);
        core_sessions.close(session_id);

        Ok(true)
    }

    /// Discard all unfinished uploads and close their Core sessions.
    pub fn close_all(&mut self, core_sessions: &mut SessionManager) -> usize {
        let session_ids: Vec<u128> = self.active_sessions.drain().collect();

        for session_id in &session_ids {
            core_sessions.close(*session_id);
        }

        self.uploads.clear();
        self.active_downloads.clear();
        session_ids.len()
    }

    pub fn contains_upload(&self, session_id: u128) -> bool {
        self.uploads.contains_key(&session_id)
    }

    pub fn len(&self) -> usize {
        self.uploads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.uploads.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "myssh-file-session-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));

        fs::create_dir_all(&root).unwrap();
        root
    }

    fn make_manager(root: &PathBuf) -> FileTransferSessionManager {
        let store = HostFileStore::new(root, 1024 * 1024).unwrap();
        FileTransferSessionManager::new(store)
    }

    fn open_transfer(manager: &mut FileTransferSessionManager, core: &mut SessionManager) -> u128 {
        let request = Frame::new(
            MessageKind::SessionOpen,
            0,
            1,
            SessionOpenPayload {
                session_type: SessionType::FileTransfer,
            }
            .encode(),
        )
        .unwrap();

        let response = manager.accept_open_request(core, &request).unwrap();
        assert_eq!(response.header.kind, MessageKind::SessionOpened);

        let opened = SessionOpenedPayload::decode(&response.payload).unwrap();
        assert_eq!(opened.status, SessionOpenStatus::Accepted);
        assert_ne!(response.header.session_id, 0);

        response.header.session_id
    }

    fn begin_frame(session_id: u128, path: &str, size: u64) -> Frame {
        Frame::new(
            MessageKind::FileBegin,
            session_id,
            2,
            FileBeginPayload {
                direction: FileDirection::Upload,
                file_size: size,
                remote_path: path.to_owned(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap()
    }

    fn chunk_frame(session_id: u128, index: u64, data: &[u8]) -> Frame {
        Frame::new(
            MessageKind::FileChunk,
            session_id,
            3 + index,
            FileChunkPayload {
                chunk_index: index,
                data: data.to_vec(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap()
    }

    fn end_frame(session_id: u128, data: &[u8], chunks: u64) -> Frame {
        Frame::new(
            MessageKind::FileEnd,
            session_id,
            100,
            FileEndPayload {
                total_chunks: chunks,
                total_size: data.len() as u64,
                sha256: Sha256::digest(data).into(),
            }
            .encode(),
        )
        .unwrap()
    }

    #[test]
    fn upload_session_commits_verified_file() {
        let root = test_root();
        let mut manager = make_manager(&root);
        let mut core = SessionManager::new();
        let session_id = open_transfer(&mut manager, &mut core);
        let data = b"MySSH upload bridge test";

        let ready = manager
            .handle_begin(
                &core,
                &begin_frame(session_id, "report.txt", data.len() as u64),
            )
            .unwrap();

        let ready = FileResponsePayload::decode(&ready.payload).unwrap();
        assert_eq!(ready.status, FileResponseStatus::Ready);
        assert_eq!(ready.error_code, FileErrorCode::None);

        manager
            .handle_chunk(&core, &chunk_frame(session_id, 0, data))
            .unwrap();

        let completed = manager
            .handle_end(&core, &end_frame(session_id, data, 1))
            .unwrap();

        let completed = FileResponsePayload::decode(&completed.payload).unwrap();
        assert_eq!(completed.status, FileResponseStatus::Completed);
        assert_eq!(fs::read(root.join("report.txt")).unwrap(), data);
        assert!(!manager.contains_upload(session_id));

        manager.close(&mut core, session_id).unwrap();
        assert!(!core.contains(session_id));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejected_upload_does_not_create_transaction() {
        let root = test_root();
        fs::write(root.join("existing.txt"), b"original").unwrap();

        let mut manager = make_manager(&root);
        let mut core = SessionManager::new();
        let session_id = open_transfer(&mut manager, &mut core);

        let response = manager
            .handle_begin(&core, &begin_frame(session_id, "existing.txt", 8))
            .unwrap();

        let response = FileResponsePayload::decode(&response.payload).unwrap();
        assert_eq!(response.status, FileResponseStatus::Rejected);
        assert_eq!(response.error_code, FileErrorCode::AlreadyExists);
        assert!(!manager.contains_upload(session_id));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_chunk_discards_temporary_upload() {
        let root = test_root();
        let mut manager = make_manager(&root);
        let mut core = SessionManager::new();
        let session_id = open_transfer(&mut manager, &mut core);

        manager
            .handle_begin(&core, &begin_frame(session_id, "partial.txt", 10))
            .unwrap();

        assert!(manager.contains_upload(session_id));

        let invalid_chunk = chunk_frame(session_id, 1, b"wrong-index");
        assert!(manager.handle_chunk(&core, &invalid_chunk).is_err());
        assert!(!manager.contains_upload(session_id));

        let entries: Vec<_> = fs::read_dir(&root).unwrap().collect();
        assert!(entries.is_empty(), "Temporary upload file was not removed");

        manager.close(&mut core, session_id).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn closing_session_discards_unfinished_upload() {
        let root = test_root();
        let mut manager = make_manager(&root);
        let mut core = SessionManager::new();
        let session_id = open_transfer(&mut manager, &mut core);

        manager
            .handle_begin(&core, &begin_frame(session_id, "unfinished.txt", 20))
            .unwrap();

        assert!(manager.contains_upload(session_id));
        manager.close(&mut core, session_id).unwrap();

        assert!(!manager.contains_upload(session_id));
        assert!(!core.contains(session_id));
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn close_all_discards_all_active_uploads() {
        let root = test_root();
        let mut manager = make_manager(&root);
        let mut core = SessionManager::new();

        let first = open_transfer(&mut manager, &mut core);
        let second = open_transfer(&mut manager, &mut core);

        manager
            .handle_begin(&core, &begin_frame(first, "first.tmp", 10))
            .unwrap();
        manager
            .handle_begin(&core, &begin_frame(second, "second.tmp", 10))
            .unwrap();

        assert_eq!(manager.close_all(&mut core), 2);
        assert!(manager.is_empty());
        assert_eq!(core.len(), 0);
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }
}
