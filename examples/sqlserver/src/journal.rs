//! A local, durable intent/result journal; not a distributed fencing mechanism.
//!
//! Only Unix hosts with stable, local persistent filesystems are supported. The
//! caller owns the containing directory and must not replace the database or
//! `.lock` sidecar inode while open.
//! Network filesystems, hard-linked database files, and in-memory SQLite are not
//! supported. Proof authentication and native postcondition checks are caller
//! responsibilities, never conclusions drawn from a stored receipt or SQL ACK.
//! Integrity hashes detect accidental corruption, not malicious file rewriting.
//! The file lock cannot cancel SQL still executing after client disconnect; the
//! adapter must also serialize native effects, for example with a session applock.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fs2::FileExt;
use rusqlite::types::ValueRef;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};

use crate::codec::{MAX_ENVELOPE_BYTES, decode_envelope, encode_envelope};
use crate::operation::OperationEnvelope;
use crate::types::OpaqueId;

pub const JOURNAL_SCHEMA_VERSION: u32 = 1;
pub const MAX_ACTION_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
pub const MAX_AUTHORITY_BINDING_BYTES: usize = 4096;
pub const MAX_ACTIONS_PER_OPERATION: usize = 128;
const APPLICATION_ID: i64 = 0x4b53514a;

const METADATA_SCHEMA: &str = "CREATE TABLE journal_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    resource_id TEXT NOT NULL,
    configuration_id TEXT,
    epoch BLOB,
    binding BLOB,
    state_hash BLOB NOT NULL CHECK (length(state_hash) = 32),
    CHECK ((configuration_id IS NULL AND epoch IS NULL AND binding IS NULL)
        OR (configuration_id IS NOT NULL AND epoch IS NOT NULL AND length(epoch) = 8
            AND binding IS NOT NULL AND length(binding) BETWEEN 1 AND 4096))
) STRICT";

const OPERATIONS_SCHEMA: &str = "CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    input_signature BLOB NOT NULL CHECK (length(input_signature) = 32),
    effect_signature BLOB NOT NULL CHECK (length(effect_signature) = 32),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536),
    result BLOB CHECK (result IS NULL OR length(result) <= 65536),
    result_hash BLOB,
    record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
    pending INTEGER UNIQUE CHECK (pending IS NULL OR pending = 1),
    CHECK ((result IS NULL AND result_hash IS NULL AND pending IS NOT NULL AND pending = 1)
        OR (result IS NOT NULL AND result_hash IS NOT NULL
            AND length(result_hash) = 32 AND pending IS NULL))
) STRICT";

const ACTIONS_SCHEMA: &str = "CREATE TABLE actions (
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    action_key TEXT NOT NULL,
    payload BLOB NOT NULL CHECK (length(payload) <= 65536),
    payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
    acknowledged INTEGER NOT NULL CHECK (acknowledged IN (0, 1)),
    PRIMARY KEY (operation_id, action_key)
) STRICT";

const EFFECT_INDEX: &str = "CREATE INDEX operations_effect ON operations(effect_signature)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    Busy,
    Io,
    Storage,
    UnsupportedPlatform,
    InvalidPath,
    InvalidInput,
    InvalidEnvelope,
    ResourceMismatch,
    UnsupportedSchemaVersion,
    CorruptSchema,
    CorruptRecord,
    AuthorityRequired,
    AuthorityRegression,
    AuthorityConflict,
    AuthorityMismatch,
    OperationInProgress,
    OperationIdReuse,
    UnknownOperation,
    UnknownAction,
    ActionConflict,
    TerminalOperation,
    ResultConflict,
    NotDuplicateEffect,
    TooLarge,
    TooManyActions,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => "operation journal is already in use",
            Self::Io => "operation journal filesystem operation failed",
            Self::Storage => "operation journal durable storage operation failed",
            Self::UnsupportedPlatform => "operation journal requires Unix local file locking",
            Self::InvalidPath => "operation journal requires a stable, single-link regular file",
            Self::InvalidInput => "invalid operation journal identifier or authority binding",
            Self::InvalidEnvelope => "invalid operation envelope",
            Self::ResourceMismatch => "operation journal belongs to another resource",
            Self::UnsupportedSchemaVersion => "unsupported operation journal schema version",
            Self::CorruptSchema => "operation journal schema is invalid or corrupt",
            Self::CorruptRecord => "operation journal record is invalid or corrupt",
            Self::AuthorityRequired => "operation journal has no accepted authority",
            Self::AuthorityRegression => "operation journal authority epoch cannot regress",
            Self::AuthorityConflict => "same-epoch operation authority binding differs",
            Self::AuthorityMismatch => "operation does not match the accepted authority",
            Self::OperationInProgress => "another operation is unresolved",
            Self::OperationIdReuse => "operation ID was reused with different canonical input",
            Self::UnknownOperation => "operation is not registered",
            Self::UnknownAction => "action intent is not registered",
            Self::ActionConflict => "action key was reused with different intent",
            Self::TerminalOperation => "a terminal operation cannot accept new action state",
            Self::ResultConflict => "terminal operation result is immutable",
            Self::NotDuplicateEffect => "operation has no registered duplicate effect",
            Self::TooLarge => "operation journal value exceeds its size limit",
            Self::TooManyActions => "operation journal action count exceeds its limit",
        })
    }
}

impl Error for JournalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAuthority {
    pub configuration_id: String,
    pub epoch: u64,
    pub binding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    New,
    Pending,
    Completed(Vec<u8>),
    /// No record is inserted for the candidate ID. This is an observation-only
    /// outcome, not permission to dispatch or to borrow the old completion.
    /// A pending owner must resolve first. With a terminal owner, reobserve,
    /// then use `finish_observed_duplicate` for the candidate.
    DuplicateEffect {
        operation_id: String,
        result: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionIntent {
    pub action_key: String,
    pub action_payload: Vec<u8>,
    /// A SQL reply was received; this is not a native postcondition or success.
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub envelope: OperationEnvelope,
    /// All immutable action intents are retained, including after completion.
    pub actions: Vec<ActionIntent>,
    pub terminal_result: Option<Vec<u8>>,
}

impl JournalEntry {
    pub fn acknowledged_action_keys(&self) -> impl Iterator<Item = &str> {
        self.actions
            .iter()
            .filter(|action| action.acknowledged)
            .map(|action| action.action_key.as_str())
    }

    pub fn pending_intents(&self) -> impl Iterator<Item = &ActionIntent> {
        self.actions.iter().filter(|action| !action.acknowledged)
    }
}

/// SQLite `synchronous=FULL` transactions protected by a non-expiring,
/// lifetime-held exclusive OS advisory lock. There is no ownership lease.
///
/// Mutating methods return only after a durable commit. An I/O error is
/// uncertainty, never a success-shaped fallback. Keep the journal and its
/// rollback-journal sidecar on the same local persistent filesystem.
/// All writers for a resource must use this same stable journal path.
pub struct OperationJournal {
    // Drop the SQLite connection before releasing the advisory lock.
    connection: Connection,
    _lock: JournalLock,
    resource_id: String,
    path: PathBuf,
}

struct JournalLock {
    file: File,
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        // Closing only this FD can leave flock held by an incidental inherited
        // descriptor while a concurrently spawned child is still before exec.
        // Release when the journal's ownership ends, after SQLite has closed.
        let _ = FileExt::unlock(&self.file);
    }
}

impl OperationJournal {
    /// The parent directory must exist. New database and lock files are mode
    /// 0600 (subject to umask); the lock sidecar is intentionally never unlinked.
    /// Symlink aliases resolve to the same journal; hard links are rejected.
    pub fn open(path: &Path, resource_id: &str) -> Result<Self, JournalError> {
        if !cfg!(unix) {
            return Err(JournalError::UnsupportedPlatform);
        }
        validate_id(resource_id)?;
        let path = resolve_path(path)?;
        let mut lock_name = path
            .file_name()
            .ok_or(JournalError::InvalidPath)?
            .to_os_string();
        lock_name.push(".lock");
        let lock_path = path.with_file_name(lock_name);
        let lock = open_regular_file(&lock_path)?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock
                || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
            {
                JournalError::Busy
            } else {
                JournalError::Io
            }
        })?;
        let lock = JournalLock { file: lock };
        verify_file(&lock_path, &lock.file)?;
        // Lock a sidecar, not SQLite's inode: flock and SQLite's own byte-range
        // locks can conflict on the same file (notably on macOS). Acquire it
        // before opening any extra database FD, whose close can release POSIX
        // SQLite locks held by another connection in this process.
        let database_file = open_regular_file(&path)?;
        let database_metadata = database_file.metadata().map_err(|_| JournalError::Io)?;
        verify_file(&path, &database_file)?;
        let was_empty = database_metadata.len() == 0;
        drop(database_file);
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql_error)?;
        connection.busy_timeout(Duration::ZERO).map_err(sql_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA trusted_schema = OFF;
                 PRAGMA synchronous = FULL;",
            )
            .map_err(sql_error)?;
        initialize_or_validate(&mut connection, resource_id, was_empty)?;
        let mode: String = connection
            .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
            .map_err(sql_error)?;
        if mode != "delete" {
            return Err(JournalError::Storage);
        }
        verify_path_identity(&path, &database_metadata)?;
        verify_file(&lock_path, &lock.file)?;
        // Also covers a process that died after creating the inode but before
        // initializing it: the next opener did not itself create the file.
        lock.file.sync_all().map_err(|_| JournalError::Io)?;
        sync_parent(&path)?;
        Ok(Self {
            connection,
            _lock: lock,
            resource_id: resource_id.to_owned(),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    pub fn authority(&self) -> Result<Option<AcceptedAuthority>, JournalError> {
        load_authority(&self.connection, &self.resource_id)
    }

    /// Call only after independently authenticating the configuration and
    /// authority fingerprint. Even a higher epoch cannot replace authority
    /// while an operation is unresolved; recovering it must not lose its fence.
    pub fn accept_authority(
        &mut self,
        configuration_id: &str,
        epoch: u64,
        binding: &[u8],
    ) -> Result<(), JournalError> {
        validate_id(configuration_id)?;
        if binding.is_empty() {
            return Err(JournalError::InvalidInput);
        }
        bounded(binding, MAX_AUTHORITY_BINDING_BYTES)?;
        let candidate = AcceptedAuthority {
            configuration_id: configuration_id.to_owned(),
            epoch,
            binding: binding.to_vec(),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(current) = load_authority(&transaction, &self.resource_id)? {
            if epoch < current.epoch {
                return Err(JournalError::AuthorityRegression);
            }
            if epoch == current.epoch {
                return if candidate == current {
                    Ok(())
                } else {
                    Err(JournalError::AuthorityConflict)
                };
            }
        }
        if has_pending(&transaction)? {
            return Err(JournalError::OperationInProgress);
        }
        store_authority(&transaction, &self.resource_id, Some(&candidate))?;
        transaction.commit().map_err(sql_error)
    }

    /// A completed exact duplicate is a read-only replay, even if authority has
    /// subsequently advanced. Pending/new work must match accepted authority.
    /// Renewed approval/fence references may replace pending references only
    /// when the complete canonical request is unchanged.
    /// Enabled callers must authenticate the request first. Observe-only
    /// callers must use `lookup` or `entry`, never registration.
    pub fn register(&mut self, envelope: &OperationEnvelope) -> Result<Registration, JournalError> {
        validate_envelope(envelope, &self.resource_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let authority = load_authority(&transaction, &self.resource_id)?;
        if let Some(mut existing) =
            load_entry(&transaction, &self.resource_id, envelope.operation_id())?
        {
            same_input(&existing, envelope)?;
            if let Some(result) = existing.terminal_result {
                return Ok(Registration::Completed(result));
            }
            require_authority(authority.as_ref(), envelope)?;
            existing.envelope = envelope.clone();
            store_entry(&transaction, &existing)?;
            transaction.commit().map_err(sql_error)?;
            return Ok(Registration::Pending);
        }
        require_authority(authority.as_ref(), envelope)?;
        if let Some(existing) = find_effect(&transaction, &self.resource_id, envelope)? {
            return Ok(Registration::DuplicateEffect {
                operation_id: existing.envelope.operation_id().to_owned(),
                result: existing.terminal_result,
            });
        }
        if has_pending(&transaction)? {
            return Err(JournalError::OperationInProgress);
        }
        store_entry(
            &transaction,
            &JournalEntry {
                envelope: envelope.clone(),
                actions: Vec::new(),
                terminal_result: None,
            },
        )?;
        transaction.commit().map_err(sql_error)?;
        Ok(Registration::New)
    }

    /// Read-only exact-ID lookup for observation and recovery. No request
    /// authentication or accepted authority is required and no references,
    /// acknowledgments, results, or authority high-water values are changed.
    pub fn entry(&self, operation_id: &str) -> Result<Option<JournalEntry>, JournalError> {
        validate_id(operation_id)?;
        load_authority(&self.connection, &self.resource_id)?;
        load_entry(&self.connection, &self.resource_id, operation_id)
    }

    /// Read-only request lookup, preferring its exact ID and otherwise finding
    /// the same canonical effect. A differing returned operation ID denotes a
    /// duplicate effect, not authorization to dispatch or borrow its result.
    /// Exact-ID input conflicts are rejected without updating proof references.
    /// This works without accepting authority, including in observe-only mode.
    pub fn lookup(
        &self,
        envelope: &OperationEnvelope,
    ) -> Result<Option<JournalEntry>, JournalError> {
        validate_envelope(envelope, &self.resource_id)?;
        load_authority(&self.connection, &self.resource_id)?;
        if let Some(existing) =
            load_entry(&self.connection, &self.resource_id, envelope.operation_id())?
        {
            same_input(&existing, envelope)?;
            return Ok(Some(existing));
        }
        find_effect(&self.connection, &self.resource_id, envelope)
    }

    /// Commit before attempting the native action. Identical retries are safe;
    /// changing the payload for a previously prepared key is never permitted.
    /// An unacknowledged intent means "possibly dispatched", not "not executed".
    /// This is preparation only: a later dispatch needs fresh observations and
    /// per-action authorization. Payloads are opaque canonical NativeAction JSON
    /// supplied by the caller and never deserialized here. Do not include
    /// credentials or executable SQL.
    pub fn persist_intent(
        &mut self,
        operation_id: &str,
        action_key: &str,
        action_payload: &[u8],
    ) -> Result<(), JournalError> {
        validate_id(operation_id)?;
        validate_id(action_key)?;
        bounded(action_payload, MAX_ACTION_PAYLOAD_BYTES)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut entry = load_entry(&transaction, &self.resource_id, operation_id)?
            .ok_or(JournalError::UnknownOperation)?;
        if entry.terminal_result.is_some() {
            return Err(JournalError::TerminalOperation);
        }
        if let Some(existing) = entry
            .actions
            .iter()
            .find(|action| action.action_key == action_key)
        {
            return if existing.action_payload == action_payload {
                Ok(())
            } else {
                Err(JournalError::ActionConflict)
            };
        }
        require_authority(
            load_authority(&transaction, &self.resource_id)?.as_ref(),
            &entry.envelope,
        )?;
        if entry.actions.len() >= MAX_ACTIONS_PER_OPERATION {
            return Err(JournalError::TooManyActions);
        }
        entry.actions.push(ActionIntent {
            action_key: action_key.to_owned(),
            action_payload: action_payload.to_vec(),
            acknowledged: false,
        });
        entry
            .actions
            .sort_by(|left, right| left.action_key.cmp(&right.action_key));
        store_entry(&transaction, &entry)?;
        transaction.commit().map_err(sql_error)
    }

    /// Records an accepted SQL reply, without completing the operation. Failed
    /// or uncertain execution must leave its intent unacknowledged and retained.
    pub fn acknowledge_action(
        &mut self,
        operation_id: &str,
        action_key: &str,
    ) -> Result<(), JournalError> {
        validate_id(operation_id)?;
        validate_id(action_key)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut entry = load_entry(&transaction, &self.resource_id, operation_id)?
            .ok_or(JournalError::UnknownOperation)?;
        let action = entry
            .actions
            .iter_mut()
            .find(|action| action.action_key == action_key)
            .ok_or(JournalError::UnknownAction)?;
        if action.acknowledged {
            return Ok(());
        }
        if entry.terminal_result.is_some() {
            return Err(JournalError::TerminalOperation);
        }
        action.acknowledged = true;
        store_entry(&transaction, &entry)?;
        transaction.commit().map_err(sql_error)
    }

    /// Call only after verifying the native terminal postcondition. Unknown or
    /// nonterminal outcomes must remain pending. Lost SQL replies need not block
    /// an independently verified postcondition; all intents remain retained.
    pub fn finish(&mut self, operation_id: &str, result: &[u8]) -> Result<(), JournalError> {
        validate_id(operation_id)?;
        bounded(result, MAX_RESULT_BYTES)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut entry = load_entry(&transaction, &self.resource_id, operation_id)?
            .ok_or(JournalError::UnknownOperation)?;
        if let Some(existing) = entry.terminal_result {
            return if existing == result {
                Ok(())
            } else {
                Err(JournalError::ResultConflict)
            };
        }
        entry.terminal_result = Some(result.to_vec());
        store_entry(&transaction, &entry)?;
        transaction.commit().map_err(sql_error)
    }

    /// Retains a result for a new ID ONLY after the caller independently
    /// reobserved its duplicate effect. Never copies the existing result or
    /// permits dispatch for this unregistered ID. The original must already
    /// be terminal and no unresolved operation may own native work. The original
    /// result and action history are left intact.
    pub fn finish_observed_duplicate(
        &mut self,
        envelope: &OperationEnvelope,
        observed_result: &[u8],
    ) -> Result<(), JournalError> {
        validate_envelope(envelope, &self.resource_id)?;
        bounded(observed_result, MAX_RESULT_BYTES)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if let Some(existing) =
            load_entry(&transaction, &self.resource_id, envelope.operation_id())?
        {
            same_input(&existing, envelope)?;
            return match existing.terminal_result {
                Some(result) if result == observed_result => Ok(()),
                Some(_) => Err(JournalError::ResultConflict),
                None => Err(JournalError::OperationInProgress),
            };
        }
        require_authority(
            load_authority(&transaction, &self.resource_id)?.as_ref(),
            envelope,
        )?;
        if find_effect(&transaction, &self.resource_id, envelope)?.is_none() {
            return Err(JournalError::NotDuplicateEffect);
        }
        if has_pending(&transaction)? {
            return Err(JournalError::OperationInProgress);
        }
        store_entry(
            &transaction,
            &JournalEntry {
                envelope: envelope.clone(),
                actions: Vec::new(),
                terminal_result: Some(observed_result.to_vec()),
            },
        )?;
        transaction.commit().map_err(sql_error)
    }
}

fn initialize_or_validate(
    connection: &mut Connection,
    resource_id: &str,
    was_empty: bool,
) -> Result<(), JournalError> {
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql_error)?;
    let app: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(sql_error)?;
    if version == 0 && app == 0 && was_empty {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        for schema in [
            METADATA_SCHEMA,
            OPERATIONS_SCHEMA,
            ACTIONS_SCHEMA,
            EFFECT_INDEX,
        ] {
            transaction.execute_batch(schema).map_err(sql_error)?;
        }
        transaction
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(sql_error)?;
        transaction
            .pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION)
            .map_err(sql_error)?;
        store_authority(&transaction, resource_id, None)?;
        transaction.commit().map_err(sql_error)?;
    } else {
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchemaVersion);
        }
        if app != APPLICATION_ID {
            return Err(JournalError::CorruptSchema);
        }
    }
    let mut schema = connection
        .prepare("SELECT name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(sql_error)?;
    let definitions = schema
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    let expected = [
        ("actions", ACTIONS_SCHEMA),
        ("journal_metadata", METADATA_SCHEMA),
        ("operations", OPERATIONS_SCHEMA),
        ("operations_effect", EFFECT_INDEX),
    ];
    if definitions.len() != expected.len()
        || definitions
            .iter()
            .zip(expected)
            .any(|((name, sql), (expected_name, expected_sql))| {
                name != expected_name || sql != expected_sql
            })
    {
        return Err(JournalError::CorruptSchema);
    }
    let check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sql_error)?;
    if check != "ok" {
        return Err(JournalError::CorruptSchema);
    }
    if connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(sql_error)?
        .exists([])
        .map_err(sql_error)?
    {
        return Err(JournalError::CorruptRecord);
    }
    let authority = load_authority(connection, resource_id)?;
    let mut statement = connection
        .prepare("SELECT operation_id FROM operations")
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let operation_id = read_text(row, 0).map_err(sql_error)?;
        let entry = load_entry(connection, resource_id, &operation_id)?
            .ok_or(JournalError::CorruptRecord)?;
        let accepted = authority.as_ref().ok_or(JournalError::CorruptRecord)?;
        let request = entry.envelope.request();
        if request.source_epoch() > accepted.epoch
            || (request.source_epoch() == accepted.epoch
                && request.source_configuration_id() != accepted.configuration_id)
            || (entry.terminal_result.is_none()
                && require_authority(Some(accepted), &entry.envelope).is_err())
        {
            return Err(JournalError::CorruptRecord);
        }
    }
    Ok(())
}

fn load_authority(
    connection: &Connection,
    resource_id: &str,
) -> Result<Option<AcceptedAuthority>, JournalError> {
    let (resource, configuration, epoch, binding, hash) = connection
        .query_row(
            "SELECT resource_id, configuration_id, epoch, binding, state_hash
             FROM journal_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    read_text(row, 0)?,
                    read_optional_text(row, 1)?,
                    read_optional_blob(row, 2, 8)?,
                    read_optional_blob(row, 3, MAX_AUTHORITY_BINDING_BYTES)?,
                    read_blob(row, 4, 32)?,
                ))
            },
        )
        .map_err(sql_error)?;
    validate_id(&resource).map_err(|_| JournalError::CorruptRecord)?;
    let authority = match (configuration, epoch, binding) {
        (None, None, None) => None,
        (Some(configuration_id), Some(epoch), Some(binding)) if !binding.is_empty() => {
            validate_id(&configuration_id).map_err(|_| JournalError::CorruptRecord)?;
            Some(AcceptedAuthority {
                configuration_id,
                epoch: u64::from_be_bytes(
                    epoch.try_into().map_err(|_| JournalError::CorruptRecord)?,
                ),
                binding,
            })
        }
        _ => return Err(JournalError::CorruptRecord),
    };
    if hash != authority_hash(&resource, authority.as_ref()) {
        return Err(JournalError::CorruptRecord);
    }
    if resource != resource_id {
        return Err(JournalError::ResourceMismatch);
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM journal_metadata", [], |row| {
            row.get(0)
        })
        .map_err(sql_error)?;
    if count != 1 {
        return Err(JournalError::CorruptRecord);
    }
    Ok(authority)
}

fn store_authority(
    connection: &Transaction<'_>,
    resource_id: &str,
    authority: Option<&AcceptedAuthority>,
) -> Result<(), JournalError> {
    let epoch = authority.map(|authority| authority.epoch.to_be_bytes());
    connection
        .execute(
            "INSERT INTO journal_metadata
                (singleton, resource_id, configuration_id, epoch, binding, state_hash)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                configuration_id = excluded.configuration_id,
                epoch = excluded.epoch, binding = excluded.binding, state_hash = excluded.state_hash",
            params![
                resource_id,
                authority.map(|authority| authority.configuration_id.as_str()),
                epoch.as_ref().map(|epoch| epoch.as_slice()),
                authority.map(|authority| authority.binding.as_slice()),
                authority_hash(resource_id, authority).as_slice(),
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn load_entry(
    connection: &Connection,
    resource_id: &str,
    operation_id: &str,
) -> Result<Option<JournalEntry>, JournalError> {
    let record = connection
        .query_row(
            "SELECT envelope, input_signature, effect_signature, result, result_hash,
                record_hash, pending FROM operations WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    read_blob(row, 0, MAX_ENVELOPE_BYTES)?,
                    read_blob(row, 1, 32)?,
                    read_blob(row, 2, 32)?,
                    read_optional_blob(row, 3, MAX_RESULT_BYTES)?,
                    read_optional_blob(row, 4, 32)?,
                    read_blob(row, 5, 32)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(sql_error)?;
    let Some((encoded, input, effect, result, result_hash, record_hash, pending)) = record else {
        return Ok(None);
    };
    let envelope = decode_envelope(&encoded).map_err(|_| JournalError::CorruptRecord)?;
    if envelope.operation_id() != operation_id
        || envelope.request().resource_id() != resource_id
        || input != envelope.input_signature().as_bytes()
        || effect != envelope.effect_signature().as_bytes()
    {
        return Err(JournalError::CorruptRecord);
    }
    match (&result, &result_hash, pending) {
        (None, None, Some(1)) => {}
        (Some(result), Some(hash), None) if hash.as_slice() == digest(result) => {}
        _ => return Err(JournalError::CorruptRecord),
    }
    let mut statement = connection
        .prepare(
            "SELECT action_key, payload, payload_hash, acknowledged FROM actions
             WHERE operation_id = ?1 ORDER BY action_key LIMIT ?2",
        )
        .map_err(sql_error)?;
    let mut rows = statement
        .query(params![
            operation_id,
            (MAX_ACTIONS_PER_OPERATION + 1) as i64
        ])
        .map_err(sql_error)?;
    let mut actions = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        if actions.len() == MAX_ACTIONS_PER_OPERATION {
            return Err(JournalError::CorruptRecord);
        }
        let action_key = read_text(row, 0).map_err(sql_error)?;
        validate_id(&action_key).map_err(|_| JournalError::CorruptRecord)?;
        let action_payload = read_blob(row, 1, MAX_ACTION_PAYLOAD_BYTES).map_err(sql_error)?;
        let hash = read_blob(row, 2, 32).map_err(sql_error)?;
        if hash != digest(&action_payload) {
            return Err(JournalError::CorruptRecord);
        }
        let acknowledged = match row.get::<_, i64>(3).map_err(sql_error)? {
            0 => false,
            1 => true,
            _ => return Err(JournalError::CorruptRecord),
        };
        actions.push(ActionIntent {
            action_key,
            action_payload,
            acknowledged,
        });
    }
    let entry = JournalEntry {
        envelope,
        actions,
        terminal_result: result,
    };
    if record_hash != entry_hash(&entry, &encoded) {
        return Err(JournalError::CorruptRecord);
    }
    Ok(Some(entry))
}

fn store_entry(connection: &Transaction<'_>, entry: &JournalEntry) -> Result<(), JournalError> {
    let encoded = encode_envelope(&entry.envelope).map_err(|_| JournalError::InvalidEnvelope)?;
    let result_hash = entry.terminal_result.as_deref().map(digest);
    connection
        .execute(
            "INSERT INTO operations
                (operation_id, input_signature, effect_signature, envelope,
                 result, result_hash, record_hash, pending)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(operation_id) DO UPDATE SET
                envelope = excluded.envelope, result = excluded.result,
                result_hash = excluded.result_hash, record_hash = excluded.record_hash,
                pending = excluded.pending",
            params![
                entry.envelope.operation_id(),
                entry.envelope.input_signature().as_bytes().as_slice(),
                entry.envelope.effect_signature().as_bytes().as_slice(),
                encoded,
                entry.terminal_result.as_deref(),
                result_hash.as_ref().map(|hash| hash.as_slice()),
                entry_hash(entry, &encoded).as_slice(),
                entry.terminal_result.is_none().then_some(1),
            ],
        )
        .map_err(sql_error)?;
    // Rewriting the complete action set and its containing record hash in ONE
    // transaction also detects deleted intents and accidental ACK-bit changes.
    connection
        .execute(
            "DELETE FROM actions WHERE operation_id = ?1",
            [entry.envelope.operation_id()],
        )
        .map_err(sql_error)?;
    for action in &entry.actions {
        connection
            .execute(
                "INSERT INTO actions
                    (operation_id, action_key, payload, payload_hash, acknowledged)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.envelope.operation_id(),
                    action.action_key,
                    action.action_payload,
                    digest(&action.action_payload).as_slice(),
                    i64::from(action.acknowledged),
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn find_effect(
    connection: &Connection,
    resource_id: &str,
    envelope: &OperationEnvelope,
) -> Result<Option<JournalEntry>, JournalError> {
    let mut statement = connection
        .prepare(
            "SELECT operation_id FROM operations WHERE effect_signature = ?1
             ORDER BY pending DESC, operation_id",
        )
        .map_err(sql_error)?;
    let mut rows = statement
        .query([envelope.effect_signature().as_bytes().as_slice()])
        .map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = read_text(row, 0).map_err(sql_error)?;
        let entry = load_entry(connection, resource_id, &id)?.ok_or(JournalError::CorruptRecord)?;
        if entry.envelope.canonical_effect() == envelope.canonical_effect() {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn has_pending(connection: &Connection) -> Result<bool, JournalError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE pending = 1)",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)
}

fn require_authority(
    authority: Option<&AcceptedAuthority>,
    envelope: &OperationEnvelope,
) -> Result<(), JournalError> {
    let authority = authority.ok_or(JournalError::AuthorityRequired)?;
    if authority.epoch != envelope.request().source_epoch()
        || authority.configuration_id != envelope.request().source_configuration_id()
    {
        return Err(JournalError::AuthorityMismatch);
    }
    Ok(())
}

fn same_input(entry: &JournalEntry, envelope: &OperationEnvelope) -> Result<(), JournalError> {
    if entry.envelope.canonical_input() != envelope.canonical_input() {
        return Err(JournalError::OperationIdReuse);
    }
    Ok(())
}

fn validate_envelope(envelope: &OperationEnvelope, resource_id: &str) -> Result<(), JournalError> {
    if envelope.request().resource_id() != resource_id {
        return Err(JournalError::ResourceMismatch);
    }
    encode_envelope(envelope).map_err(|_| JournalError::InvalidEnvelope)?;
    Ok(())
}

fn authority_hash(resource: &str, authority: Option<&AcceptedAuthority>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash_field(&mut hash, b"kuberic.sqlserver.journal.authority.v1");
    hash_field(&mut hash, resource.as_bytes());
    match authority {
        Some(authority) => {
            hash.update([1]);
            hash_field(&mut hash, authority.configuration_id.as_bytes());
            hash.update(authority.epoch.to_be_bytes());
            hash_field(&mut hash, &authority.binding);
        }
        None => hash.update([0]),
    }
    hash.finalize().into()
}

fn entry_hash(entry: &JournalEntry, encoded: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash_field(&mut hash, b"kuberic.sqlserver.journal.entry.v1");
    hash_field(&mut hash, entry.envelope.operation_id().as_bytes());
    hash_field(&mut hash, encoded);
    match &entry.terminal_result {
        Some(result) => {
            hash.update([1]);
            hash_field(&mut hash, result);
        }
        None => hash.update([0]),
    }
    hash.update((entry.actions.len() as u64).to_be_bytes());
    for action in &entry.actions {
        hash_field(&mut hash, action.action_key.as_bytes());
        hash_field(&mut hash, &action.action_payload);
        hash.update([u8::from(action.acknowledged)]);
    }
    hash.finalize().into()
}

fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn bounded(bytes: &[u8], max: usize) -> Result<(), JournalError> {
    if bytes.len() > max {
        return Err(JournalError::TooLarge);
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), JournalError> {
    OpaqueId::new("journal identifier", id)
        .map(|_| ())
        .map_err(|_| JournalError::InvalidInput)
}

fn read_blob(row: &Row<'_>, index: usize, max: usize) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(index)? {
        ValueRef::Blob(bytes) if bytes.len() <= max => Ok(bytes.to_vec()),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn read_optional_blob(
    row: &Row<'_>,
    index: usize,
    max: usize,
) -> rusqlite::Result<Option<Vec<u8>>> {
    if matches!(row.get_ref(index)?, ValueRef::Null) {
        Ok(None)
    } else {
        read_blob(row, index, max).map(Some)
    }
}

fn read_text(row: &Row<'_>, index: usize) -> rusqlite::Result<String> {
    match row.get_ref(index)? {
        ValueRef::Text(bytes) if bytes.len() <= 256 => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn read_optional_text(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<String>> {
    if matches!(row.get_ref(index)?, ValueRef::Null) {
        Ok(None)
    } else {
        read_text(row, index).map(Some)
    }
}

fn sql_error(error: rusqlite::Error) -> JournalError {
    use rusqlite::ErrorCode;
    match error {
        rusqlite::Error::SqliteFailure(error, _) => match error.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => JournalError::Busy,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => JournalError::CorruptSchema,
            _ => JournalError::Storage,
        },
        rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::InvalidQuery
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::FromSqlConversionFailure(..) => JournalError::CorruptRecord,
        _ => JournalError::Storage,
    }
}

fn resolve_path(path: &Path) -> Result<PathBuf, JournalError> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Err(JournalError::InvalidPath);
    }
    match fs::canonicalize(path) {
        Ok(path) => {
            if !fs::metadata(&path).map_err(|_| JournalError::Io)?.is_file() {
                return Err(JournalError::InvalidPath);
            }
            Ok(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A dangling symlink is not permission to create its target.
            if fs::symlink_metadata(path).is_ok() {
                return Err(JournalError::InvalidPath);
            }
            let name = path.file_name().ok_or(JournalError::InvalidPath)?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = fs::canonicalize(parent).map_err(|_| JournalError::InvalidPath)?;
            Ok(parent.join(name))
        }
        Err(_) => Err(JournalError::Io),
    }
}

fn open_regular_file(path: &Path) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::metadata(path).map_err(|_| JournalError::Io)?;
            if !metadata.is_file() {
                return Err(JournalError::InvalidPath);
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|_| JournalError::Io)
        }
        Err(_) => Err(JournalError::Io),
    }
}

fn verify_file(path: &Path, file: &File) -> Result<(), JournalError> {
    let actual = file.metadata().map_err(|_| JournalError::Io)?;
    verify_path_identity(path, &actual)
}

fn verify_path_identity(path: &Path, actual: &fs::Metadata) -> Result<(), JournalError> {
    let current = fs::symlink_metadata(path).map_err(|_| JournalError::Io)?;
    if !actual.is_file() || !current.is_file() {
        return Err(JournalError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if actual.nlink() != 1 || actual.dev() != current.dev() || actual.ino() != current.ino() {
            return Err(JournalError::InvalidPath);
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), JournalError> {
    #[cfg(unix)]
    {
        File::open(path.parent().ok_or(JournalError::InvalidPath)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| JournalError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::{JournalError, OperationJournal};

    #[test]
    fn owner_drop_releases_lock_even_with_an_inherited_descriptor() {
        let directory = tempfile::Builder::new()
            .prefix(".sqlserver-journal-lock-test-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let path = directory.path().join("journal.db");
        let journal = OperationJournal::open(&path, "resource").unwrap();
        // dup and fork share the same open-file description, and therefore flock.
        let inherited = journal._lock.file.try_clone().unwrap();
        drop(journal);

        let next_owner = OperationJournal::open(&path, "resource").unwrap();
        drop(inherited);
        assert!(matches!(
            OperationJournal::open(&path, "resource"),
            Err(JournalError::Busy)
        ));
        drop(next_owner);
        assert!(OperationJournal::open(&path, "resource").is_ok());
    }
}
