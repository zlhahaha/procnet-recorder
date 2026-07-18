use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use procnet_core::{
    AlertRecord, EndpointSummary, ProcessSessionSummary, SessionBucket, SessionId, SessionRecord,
    SessionStatus,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug)]
pub enum StorageError {
    Database(rusqlite::Error),
    LockPoisoned,
    InvalidData(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "SQLite error: {error}"),
            Self::LockPoisoned => formatter.write_str("SQLite connection lock is poisoned"),
            Self::InvalidData(detail) => write!(formatter, "invalid persisted data: {detail}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

/// One serialized `SQLite` connection. It is safe to share with application background workers;
/// callers never receive the native connection or execute SQL themselves.
#[derive(Debug)]
pub struct Database {
    connection: Mutex<Connection>,
}

#[allow(clippy::missing_errors_doc)]
impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StorageError> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        let existing_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if existing_version > SCHEMA_VERSION {
            return Err(StorageError::InvalidData(format!(
                "database schema {existing_version} is newer than supported version {SCHEMA_VERSION}"
            )));
        }
        migrate(&connection)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StorageError::InvalidData(format!(
                "unsupported schema version {version}; expected {SCHEMA_VERSION}"
            )));
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn schema_version(&self) -> Result<i64, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn start_session(
        &self,
        name: &str,
        notes: &str,
        started_at_unix_nanos: u64,
    ) -> Result<SessionId, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        connection.execute(
            "INSERT INTO sessions(name, notes, started_at_ns, status) VALUES (?1, ?2, ?3, 'recording')",
            params![name.trim(), notes.trim(), to_i64(started_at_unix_nanos)?],
        )?;
        Ok(SessionId(connection.last_insert_rowid()))
    }

    pub fn finish_session(
        &self,
        id: SessionId,
        ended_at_unix_nanos: u64,
        status: SessionStatus,
    ) -> Result<bool, StorageError> {
        if status == SessionStatus::Recording {
            return Err(StorageError::InvalidData(
                "finished session cannot retain recording status".to_owned(),
            ));
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(connection.execute(
            "UPDATE sessions SET ended_at_ns=?1, status=?2 WHERE id=?3 AND status='recording'",
            params![to_i64(ended_at_unix_nanos)?, status.as_str(), id.0],
        )? == 1)
    }

    /// Marks sessions left recording by an unclean shutdown as interrupted.
    pub fn recover_interrupted_sessions(
        &self,
        recovered_at_unix_nanos: u64,
    ) -> Result<usize, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(connection.execute(
            "UPDATE sessions SET ended_at_ns=?1, status='interrupted' WHERE status='recording'",
            params![to_i64(recovered_at_unix_nanos)?],
        )?)
    }

    pub fn append_batch(
        &self,
        session_id: SessionId,
        buckets: &[SessionBucket],
        processes: &[ProcessSessionSummary],
        endpoints: &[EndpointSummary],
        alerts: &[AlertRecord],
    ) -> Result<(), StorageError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let transaction = connection.transaction()?;
        insert_buckets(&transaction, session_id, buckets)?;
        upsert_processes(&transaction, session_id, processes)?;
        upsert_endpoints(&transaction, session_id, endpoints)?;
        insert_alerts(&transaction, alerts)?;
        transaction.execute(
            "UPDATE sessions SET
                send_bytes=COALESCE((SELECT SUM(send_bytes) FROM session_buckets WHERE session_id=?1),0),
                receive_bytes=COALESCE((SELECT SUM(receive_bytes) FROM session_buckets WHERE session_id=?1),0),
                event_count=COALESCE((SELECT SUM(event_count) FROM session_buckets WHERE session_id=?1),0)
             WHERE id=?1",
            [session_id.0],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT id,name,notes,started_at_ns,ended_at_ns,status,send_bytes,receive_bytes,event_count
             FROM sessions ORDER BY started_at_ns DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], map_session)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn session(&self, id: SessionId) -> Result<Option<SessionRecord>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        connection
            .query_row(
                "SELECT id,name,notes,started_at_ns,ended_at_ns,status,send_bytes,receive_bytes,event_count FROM sessions WHERE id=?1",
                [id.0],
                map_session,
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn session_buckets(&self, id: SessionId) -> Result<Vec<SessionBucket>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT start_ns,send_bytes,receive_bytes,event_count FROM session_buckets WHERE session_id=?1 ORDER BY start_ns",
        )?;
        let rows = statement.query_map([id.0], |row| {
            Ok(SessionBucket {
                start_unix_nanos: to_u64(row.get(0)?)?,
                send_bytes: to_u64(row.get(1)?)?,
                receive_bytes: to_u64(row.get(2)?)?,
                event_count: to_u64(row.get(3)?)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn session_processes(
        &self,
        id: SessionId,
    ) -> Result<Vec<ProcessSessionSummary>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT pid,process_started_at_ns,name,image_path,send_bytes,receive_bytes,connection_count
             FROM session_processes WHERE session_id=?1 ORDER BY send_bytes+receive_bytes DESC,name",
        )?;
        let rows = statement.query_map([id.0], |row| {
            Ok(ProcessSessionSummary {
                pid: u32::try_from(row.get::<_, i64>(0)?).map_err(conversion_error)?,
                started_at_unix_nanos: to_u64(row.get(1)?)?,
                name: row.get(2)?,
                image_path: row.get(3)?,
                send_bytes: to_u64(row.get(4)?)?,
                receive_bytes: to_u64(row.get(5)?)?,
                connection_count: to_u64(row.get(6)?)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn session_endpoints(&self, id: SessionId) -> Result<Vec<EndpointSummary>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT protocol,remote_address,process_name,first_seen_ns,last_seen_ns,connection_count
             FROM session_endpoints WHERE session_id=?1 ORDER BY last_seen_ns DESC,remote_address",
        )?;
        let rows = statement.query_map([id.0], |row| {
            Ok(EndpointSummary {
                protocol: row.get(0)?,
                remote_address: row.get(1)?,
                process_name: row.get(2)?,
                first_seen_unix_nanos: to_u64(row.get(3)?)?,
                last_seen_unix_nanos: to_u64(row.get(4)?)?,
                connection_count: to_u64(row.get(5)?)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn session_alerts(&self, id: SessionId) -> Result<Vec<AlertRecord>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT id,occurred_at_ns,kind,title,detail,process_name,remote_address
             FROM alerts WHERE session_id=?1 ORDER BY occurred_at_ns DESC,id DESC",
        )?;
        let rows = statement.query_map([id.0], |row| {
            let kind_text: String = row.get(2)?;
            let kind = procnet_core::AlertKind::parse(&kind_text).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(
                    2,
                    "kind".to_owned(),
                    rusqlite::types::Type::Text,
                )
            })?;
            Ok(AlertRecord {
                id: row.get(0)?,
                session_id: id,
                occurred_at_unix_nanos: to_u64(row.get(1)?)?,
                kind,
                title: row.get(3)?,
                detail: row.get(4)?,
                process_name: row.get(5)?,
                remote_address: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        connection
            .query_row("SELECT value FROM settings WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(StorageError::from)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        connection.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn delete_sessions_ended_before(
        &self,
        cutoff_unix_nanos: u64,
    ) -> Result<usize, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(connection.execute(
            "DELETE FROM sessions WHERE ended_at_ns IS NOT NULL AND ended_at_ns < ?1",
            [to_i64(cutoff_unix_nanos)?],
        )?)
    }

    pub fn delete_session(&self, id: SessionId) -> Result<bool, StorageError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(connection.execute(
            "DELETE FROM sessions WHERE id=?1 AND status<>'recording'",
            [id.0],
        )? == 1)
    }
}

impl procnet_core::SessionRepository for Database {
    fn recover_interrupted(&self, timestamp: u64) -> Result<usize, String> {
        self.recover_interrupted_sessions(timestamp)
            .map_err(|error| error.to_string())
    }

    fn start_session(&self, name: &str, notes: &str, timestamp: u64) -> Result<SessionId, String> {
        self.start_session(name, notes, timestamp)
            .map_err(|error| error.to_string())
    }

    fn finish_session(
        &self,
        id: SessionId,
        timestamp: u64,
        status: SessionStatus,
    ) -> Result<bool, String> {
        self.finish_session(id, timestamp, status)
            .map_err(|error| error.to_string())
    }

    fn append_batch(
        &self,
        id: SessionId,
        buckets: &[SessionBucket],
        processes: &[ProcessSessionSummary],
        endpoints: &[EndpointSummary],
        alerts: &[AlertRecord],
    ) -> Result<(), String> {
        self.append_batch(id, buckets, processes, endpoints, alerts)
            .map_err(|error| error.to_string())
    }

    fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>, String> {
        self.list_sessions(limit).map_err(|error| error.to_string())
    }

    fn detail(&self, id: SessionId) -> Result<Option<procnet_core::SessionDetail>, String> {
        let Some(session) = self.session(id).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        Ok(Some(procnet_core::SessionDetail {
            session,
            buckets: self
                .session_buckets(id)
                .map_err(|error| error.to_string())?,
            processes: self
                .session_processes(id)
                .map_err(|error| error.to_string())?,
            endpoints: self
                .session_endpoints(id)
                .map_err(|error| error.to_string())?,
            alerts: self.session_alerts(id).map_err(|error| error.to_string())?,
        }))
    }

    fn delete_session(&self, id: SessionId) -> Result<bool, String> {
        self.delete_session(id).map_err(|error| error.to_string())
    }

    fn delete_sessions_ended_before(&self, cutoff: u64) -> Result<usize, String> {
        self.delete_sessions_ended_before(cutoff)
            .map_err(|error| error.to_string())
    }

    fn setting(&self, key: &str) -> Result<Option<String>, String> {
        self.setting(key).map_err(|error| error.to_string())
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.set_setting(key, value)
            .map_err(|error| error.to_string())
    }

    fn export_session(
        &self,
        id: SessionId,
        format: procnet_core::ExportFormat,
        path: &std::path::Path,
    ) -> Result<(), String> {
        let detail = <Self as procnet_core::SessionRepository>::detail(self, id)?
            .ok_or_else(|| format!("session {id} does not exist"))?;
        let contents = match format {
            procnet_core::ExportFormat::Json => crate::render_session_json(&detail),
            procnet_core::ExportFormat::Csv => crate::render_session_csv(&detail),
            procnet_core::ExportFormat::Markdown => crate::render_session_markdown(&detail),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(path, contents).map_err(|error| error.to_string())
    }
}

fn migrate(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS sessions(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             notes TEXT NOT NULL DEFAULT '',
             started_at_ns INTEGER NOT NULL,
             ended_at_ns INTEGER,
             status TEXT NOT NULL CHECK(status IN ('recording','completed','interrupted')),
             send_bytes INTEGER NOT NULL DEFAULT 0,
             receive_bytes INTEGER NOT NULL DEFAULT 0,
             event_count INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS session_buckets(
             session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
             start_ns INTEGER NOT NULL,
             send_bytes INTEGER NOT NULL,
             receive_bytes INTEGER NOT NULL,
             event_count INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY(session_id,start_ns)
         );
         CREATE TABLE IF NOT EXISTS session_processes(
             session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
             pid INTEGER NOT NULL,
             process_started_at_ns INTEGER NOT NULL,
             name TEXT NOT NULL,
             image_path TEXT,
             send_bytes INTEGER NOT NULL,
             receive_bytes INTEGER NOT NULL,
             connection_count INTEGER NOT NULL,
             PRIMARY KEY(session_id,pid,process_started_at_ns)
         );
         CREATE TABLE IF NOT EXISTS session_endpoints(
             session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
             protocol TEXT NOT NULL,
             remote_address TEXT NOT NULL,
             process_name TEXT NOT NULL,
             first_seen_ns INTEGER NOT NULL,
             last_seen_ns INTEGER NOT NULL,
             connection_count INTEGER NOT NULL,
             PRIMARY KEY(session_id,protocol,remote_address,process_name)
         );
         CREATE TABLE IF NOT EXISTS alerts(
             id INTEGER PRIMARY KEY,
             session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
             occurred_at_ns INTEGER NOT NULL,
             kind TEXT NOT NULL,
             title TEXT NOT NULL,
             detail TEXT NOT NULL,
             process_name TEXT,
             remote_address TEXT
         );
         CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at_ns DESC);
         CREATE INDEX IF NOT EXISTS idx_alerts_session_time ON alerts(session_id,occurred_at_ns);
         PRAGMA user_version=1;
         COMMIT;",
    )?;
    Ok(())
}

fn insert_buckets(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    buckets: &[SessionBucket],
) -> Result<(), StorageError> {
    let mut statement = transaction.prepare(
        "INSERT INTO session_buckets(session_id,start_ns,send_bytes,receive_bytes,event_count)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(session_id,start_ns) DO UPDATE SET send_bytes=excluded.send_bytes,receive_bytes=excluded.receive_bytes,event_count=excluded.event_count",
    )?;
    for bucket in buckets {
        statement.execute(params![
            session_id.0,
            to_i64(bucket.start_unix_nanos)?,
            to_i64(bucket.send_bytes)?,
            to_i64(bucket.receive_bytes)?,
            to_i64(bucket.event_count)?
        ])?;
    }
    Ok(())
}

fn upsert_processes(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    processes: &[ProcessSessionSummary],
) -> Result<(), StorageError> {
    let mut statement = transaction.prepare(
        "INSERT INTO session_processes(session_id,pid,process_started_at_ns,name,image_path,send_bytes,receive_bytes,connection_count)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(session_id,pid,process_started_at_ns) DO UPDATE SET
           name=CASE
             WHEN excluded.name GLOB 'PID [0-9]*' AND session_processes.name NOT GLOB 'PID [0-9]*'
             THEN session_processes.name
             ELSE excluded.name
           END,
           image_path=COALESCE(excluded.image_path,session_processes.image_path),
           send_bytes=excluded.send_bytes,
           receive_bytes=excluded.receive_bytes,
           connection_count=excluded.connection_count",
    )?;
    for process in processes {
        statement.execute(params![
            session_id.0,
            i64::from(process.pid),
            to_i64(process.started_at_unix_nanos)?,
            process.name,
            process.image_path,
            to_i64(process.send_bytes)?,
            to_i64(process.receive_bytes)?,
            to_i64(process.connection_count)?
        ])?;
    }
    Ok(())
}

fn upsert_endpoints(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    endpoints: &[EndpointSummary],
) -> Result<(), StorageError> {
    let mut statement = transaction.prepare(
        "INSERT INTO session_endpoints(session_id,protocol,remote_address,process_name,first_seen_ns,last_seen_ns,connection_count)
         VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(session_id,protocol,remote_address,process_name) DO UPDATE SET first_seen_ns=MIN(first_seen_ns,excluded.first_seen_ns),last_seen_ns=MAX(last_seen_ns,excluded.last_seen_ns),connection_count=excluded.connection_count",
    )?;
    for endpoint in endpoints {
        statement.execute(params![
            session_id.0,
            endpoint.protocol,
            endpoint.remote_address,
            endpoint.process_name,
            to_i64(endpoint.first_seen_unix_nanos)?,
            to_i64(endpoint.last_seen_unix_nanos)?,
            to_i64(endpoint.connection_count)?
        ])?;
    }
    Ok(())
}

fn insert_alerts(
    transaction: &Transaction<'_>,
    alerts: &[AlertRecord],
) -> Result<(), StorageError> {
    let mut statement = transaction.prepare(
        "INSERT OR IGNORE INTO alerts(id,session_id,occurred_at_ns,kind,title,detail,process_name,remote_address) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
    )?;
    for alert in alerts {
        statement.execute(params![
            alert.id,
            alert.session_id.0,
            to_i64(alert.occurred_at_unix_nanos)?,
            alert.kind.as_str(),
            alert.title,
            alert.detail,
            alert.process_name,
            alert.remote_address
        ])?;
    }
    Ok(())
}

fn map_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    let status_text: String = row.get(5)?;
    let status = SessionStatus::parse(&status_text).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(5, "status".to_owned(), rusqlite::types::Type::Text)
    })?;
    Ok(SessionRecord {
        id: SessionId(row.get(0)?),
        name: row.get(1)?,
        notes: row.get(2)?,
        started_at_unix_nanos: to_u64(row.get(3)?)?,
        ended_at_unix_nanos: row.get::<_, Option<i64>>(4)?.map(to_u64).transpose()?,
        status,
        send_bytes: to_u64(row.get(6)?)?,
        receive_bytes: to_u64(row.get(7)?)?,
        event_count: to_u64(row.get(8)?)?,
    })
}

fn to_i64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::InvalidData(format!("value {value} exceeds SQLite INTEGER")))
}

fn to_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn conversion_error(error: std::num::TryFromIntError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_session_lifecycle_and_cascade_are_durable() {
        let database = Database::open_in_memory().unwrap();
        assert_eq!(database.schema_version().unwrap(), SCHEMA_VERSION);
        let id = database.start_session("Demo", "notes", 100).unwrap();
        database
            .append_batch(
                id,
                &[SessionBucket {
                    start_unix_nanos: 100,
                    send_bytes: 12,
                    receive_bytes: 34,
                    event_count: 2,
                }],
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert!(
            database
                .finish_session(id, 200, SessionStatus::Completed)
                .unwrap()
        );
        let record = database.session(id).unwrap().unwrap();
        assert_eq!(record.status, SessionStatus::Completed);
        assert_eq!((record.send_bytes, record.receive_bytes), (12, 34));
        assert_eq!(database.session_buckets(id).unwrap().len(), 1);
        assert_eq!(database.delete_sessions_ended_before(201).unwrap(), 1);
        assert!(database.session(id).unwrap().is_none());
    }

    #[test]
    fn startup_recovery_only_interrupts_active_sessions() {
        let database = Database::open_in_memory().unwrap();
        let interrupted = database.start_session("crashed", "", 100).unwrap();
        let completed = database.start_session("done", "", 110).unwrap();
        database
            .finish_session(completed, 120, SessionStatus::Completed)
            .unwrap();
        assert_eq!(database.recover_interrupted_sessions(200).unwrap(), 1);
        assert_eq!(
            database.session(interrupted).unwrap().unwrap().status,
            SessionStatus::Interrupted
        );
        assert_eq!(
            database.session(completed).unwrap().unwrap().status,
            SessionStatus::Completed
        );
    }

    #[test]
    fn exact_session_delete_rejects_active_and_cascades_completed_children() {
        let database = Database::open_in_memory().unwrap();
        let active = database.start_session("active", "", 100).unwrap();
        let completed = database.start_session("completed", "", 110).unwrap();
        database
            .append_batch(
                completed,
                &[SessionBucket {
                    start_unix_nanos: 110,
                    send_bytes: 1,
                    receive_bytes: 2,
                    event_count: 1,
                }],
                &[],
                &[],
                &[],
            )
            .unwrap();
        database
            .finish_session(completed, 200, SessionStatus::Completed)
            .unwrap();

        assert!(!database.delete_session(active).unwrap());
        assert!(database.session(active).unwrap().is_some());
        assert!(database.delete_session(completed).unwrap());
        assert!(database.session(completed).unwrap().is_none());
        assert!(database.session_buckets(completed).unwrap().is_empty());
    }

    #[test]
    fn future_schema_is_rejected_without_downgrade() {
        let connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 999).unwrap();
        let error = Database::from_connection(connection).unwrap_err();
        assert!(error.to_string().contains("newer than supported"));
    }

    #[test]
    fn corrupt_database_returns_a_clear_error() {
        let path = std::env::temp_dir().join(format!(
            "procnet-corrupt-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"not a sqlite database").unwrap();
        let error = Database::open(&path).unwrap_err();
        assert!(error.to_string().contains("SQLite error"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn recording_controller_persists_and_completes_a_session() {
        let database = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let controller =
            procnet_application::RecordingController::start(database.clone(), 10).unwrap();
        controller
            .start_recording("integration".to_owned(), "end-to-end".to_owned(), 100)
            .unwrap();

        let runtime = procnet_application::ApplicationRuntime::start(4).unwrap();
        let mut snapshot = runtime.snapshot_reader().snapshot().unwrap();
        snapshot.network_rate.sampled_at_unix_nanos = 1_000_000_000;
        snapshot.network_rate.send_bytes_per_second = 123;
        snapshot.network_rate.receive_bytes_per_second = 456;
        snapshot.events_processed = 2;
        controller.try_record(snapshot);
        controller.stop_recording(2_000_000_000).unwrap();

        for _ in 0..100 {
            if database
                .list_sessions(1)
                .unwrap()
                .first()
                .is_some_and(|session| session.status == SessionStatus::Completed)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let session = database.list_sessions(1).unwrap().remove(0);
        assert_eq!(session.status, SessionStatus::Completed);
        assert_eq!(
            (
                session.send_bytes,
                session.receive_bytes,
                session.event_count
            ),
            (123, 456, 2)
        );
        assert_eq!(database.session_buckets(session.id).unwrap().len(), 1);
        drop(controller);
        let _ = runtime.stop();
    }

    #[test]
    fn recording_controller_keeps_resolved_process_metadata_after_process_exit() {
        let database = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let controller =
            procnet_application::RecordingController::start(database.clone(), 10).unwrap();
        controller
            .start_recording("metadata".to_owned(), "process exit".to_owned(), 100)
            .unwrap();
        let runtime = procnet_application::ApplicationRuntime::start(4).unwrap();

        let mut alive = runtime.snapshot_reader().snapshot().unwrap();
        alive.network_rate.sampled_at_unix_nanos = 1_000_000_000;
        alive.process_traffic = vec![procnet_application::ProcessTrafficSnapshot {
            pid: 42,
            process_key: Some(procnet_core::ProcessKey {
                pid: 42,
                started_at_unix_nanos: 500,
            }),
            name: Some("procnet-fixture.exe".to_owned()),
            image_path: Some("C:\\demo\\procnet-fixture.exe".to_owned()),
            icon: procnet_core::ProcessIconState::NotLoaded,
            send_bytes_total: 100,
            receive_bytes_total: 100,
            send_bytes_per_second: 100,
            receive_bytes_per_second: 100,
            connection_count: 1,
            last_timestamp_unix_nanos: 1_000_000_000,
        }];
        controller.try_record(alive);

        let mut exited = runtime.snapshot_reader().snapshot().unwrap();
        exited.network_rate.sampled_at_unix_nanos = 2_000_000_000;
        exited.process_traffic = vec![procnet_application::ProcessTrafficSnapshot {
            pid: 42,
            process_key: None,
            name: None,
            image_path: None,
            icon: procnet_core::ProcessIconState::NotLoaded,
            send_bytes_total: 200,
            receive_bytes_total: 200,
            send_bytes_per_second: 0,
            receive_bytes_per_second: 0,
            connection_count: 0,
            last_timestamp_unix_nanos: 1_000_000_000,
        }];
        controller.try_record(exited);
        controller.stop_recording(3_000_000_000).unwrap();

        for _ in 0..100 {
            if database
                .list_sessions(1)
                .unwrap()
                .first()
                .is_some_and(|session| session.status == SessionStatus::Completed)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let session = database.list_sessions(1).unwrap().remove(0);
        let processes = database.session_processes(session.id).unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].name, "procnet-fixture.exe");
        assert_eq!(processes[0].started_at_unix_nanos, 500);
        assert_eq!(
            processes[0].image_path.as_deref(),
            Some("C:\\demo\\procnet-fixture.exe")
        );

        drop(controller);
        let _ = runtime.stop();
    }

    #[test]
    fn recording_controller_persists_alerts_end_to_end() {
        let database = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let controller =
            procnet_application::RecordingController::start(database.clone(), 10).unwrap();
        controller
            .save_settings(procnet_application::V2Settings {
                upload_alert_bytes_per_second: 100,
                download_alert_bytes_per_second: 100,
                ..procnet_application::V2Settings::default()
            })
            .unwrap();
        controller
            .start_recording("alerts".to_owned(), "end-to-end".to_owned(), 100)
            .unwrap();

        let runtime = procnet_application::ApplicationRuntime::start(4).unwrap();
        let mut baseline = runtime.snapshot_reader().snapshot().unwrap();
        baseline.network_rate.sampled_at_unix_nanos = 1_000_000_000;
        controller.try_record(baseline);

        for second in 2..=4 {
            let mut snapshot = runtime.snapshot_reader().snapshot().unwrap();
            snapshot.network_rate.sampled_at_unix_nanos = second * 1_000_000_000;
            snapshot.process_traffic = vec![procnet_application::ProcessTrafficSnapshot {
                pid: 42,
                process_key: Some(procnet_core::ProcessKey {
                    pid: 42,
                    started_at_unix_nanos: 2_000_000_000,
                }),
                name: Some("fixture.exe".to_owned()),
                image_path: None,
                icon: procnet_core::ProcessIconState::NotLoaded,
                send_bytes_total: second * 100,
                receive_bytes_total: second * 100,
                send_bytes_per_second: 100,
                receive_bytes_per_second: 100,
                connection_count: 1,
                last_timestamp_unix_nanos: second * 1_000_000_000,
            }];
            snapshot.network_rate.send_bytes_per_second = 100;
            snapshot.network_rate.receive_bytes_per_second = 100;
            controller.try_record(snapshot);
        }
        controller.stop_recording(5_000_000_000).unwrap();

        for _ in 0..100 {
            let completed_with_alert = database
                .list_sessions(1)
                .unwrap()
                .first()
                .filter(|session| session.status == SessionStatus::Completed)
                .is_some_and(|session| {
                    database
                        .session_alerts(session.id)
                        .is_ok_and(|alerts| !alerts.is_empty())
                });
            if completed_with_alert {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let session = database.list_sessions(1).unwrap().remove(0);
        let alerts = database.session_alerts(session.id).unwrap();
        assert_eq!(session.status, SessionStatus::Completed);
        assert_eq!(alerts.len(), 2);
        assert!(
            alerts
                .iter()
                .all(|alert| alert.kind == procnet_core::AlertKind::RiskEvent)
        );
        assert!(alerts.iter().any(|alert| alert.title == "高风险网络活动"));

        drop(controller);
        let _ = runtime.stop();
    }

    #[test]
    fn high_risk_live_activity_creates_and_completes_an_automatic_event_session() {
        let database = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let controller =
            procnet_application::RecordingController::start(database.clone(), 10).unwrap();
        controller
            .save_settings(procnet_application::V2Settings {
                upload_alert_bytes_per_second: 100,
                download_alert_bytes_per_second: 100,
                ..procnet_application::V2Settings::default()
            })
            .unwrap();
        let runtime = procnet_application::ApplicationRuntime::start(4).unwrap();
        let reader = runtime.snapshot_reader();

        let mut baseline = reader.snapshot().unwrap();
        baseline.network_rate.sampled_at_unix_nanos = 1_000_000_000;
        controller.try_record(baseline);
        for second in 2..=4 {
            let mut snapshot = reader.snapshot().unwrap();
            snapshot.network_rate.sampled_at_unix_nanos = second * 1_000_000_000;
            snapshot.process_traffic = vec![procnet_application::ProcessTrafficSnapshot {
                pid: 42,
                process_key: Some(procnet_core::ProcessKey {
                    pid: 42,
                    started_at_unix_nanos: 2_000_000_000,
                }),
                name: Some("fixture.exe".to_owned()),
                image_path: None,
                icon: procnet_core::ProcessIconState::NotLoaded,
                send_bytes_total: second * 100,
                receive_bytes_total: second * 100,
                send_bytes_per_second: 100,
                receive_bytes_per_second: 100,
                connection_count: 1,
                last_timestamp_unix_nanos: second * 1_000_000_000,
            }];
            snapshot.network_rate.send_bytes_per_second = 100;
            snapshot.network_rate.receive_bytes_per_second = 100;
            controller.try_record(snapshot);
        }
        let mut after = reader.snapshot().unwrap();
        after.network_rate.sampled_at_unix_nanos = 65_000_000_000;
        controller.try_record(after);

        for _ in 0..100 {
            if database
                .list_sessions(1)
                .unwrap()
                .first()
                .is_some_and(|session| session.status == SessionStatus::Completed)
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let session = database.list_sessions(1).unwrap().remove(0);
        assert_eq!(session.status, SessionStatus::Completed);
        assert!(session.name.starts_with("自动高风险事件"));
        assert!(database.session_buckets(session.id).unwrap().len() >= 4);
        assert!(
            database
                .session_alerts(session.id)
                .unwrap()
                .iter()
                .any(|alert| alert.kind == procnet_core::AlertKind::RiskEvent)
        );
        assert!(
            controller
                .state()
                .live_risk_events
                .iter()
                .any(|event| event.level == procnet_core::RiskLevel::High)
        );

        drop(controller);
        let _ = runtime.stop();
    }

    #[test]
    fn recording_controller_delete_clears_selected_and_comparison_state() {
        let database = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let left = database.start_session("left", "", 100).unwrap();
        let right = database.start_session("right", "", 110).unwrap();
        database
            .finish_session(left, 120, SessionStatus::Completed)
            .unwrap();
        database
            .finish_session(right, 130, SessionStatus::Completed)
            .unwrap();
        let controller =
            procnet_application::RecordingController::start(database.clone(), 200).unwrap();
        controller.select(left).unwrap();
        controller.compare(left, right).unwrap();
        for _ in 0..100 {
            let state = controller.state();
            if state.selected.is_some() && state.compare_left.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        controller.delete_session(left).unwrap();
        for _ in 0..100 {
            let state = controller.state();
            if state.sessions.iter().all(|session| session.id != left)
                && state.selected.is_none()
                && state.compare_left.is_none()
                && state.compare_right.is_none()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let state = controller.state();
        assert!(state.sessions.iter().all(|session| session.id != left));
        assert!(state.selected.is_none());
        assert!(state.compare_left.is_none());
        assert!(state.compare_right.is_none());
        assert!(database.session(left).unwrap().is_none());
    }
}
