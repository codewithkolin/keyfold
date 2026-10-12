//! Wire protocol and client for talking to the running Keyfold app over a local
//! socket. One JSON line in, one JSON line out. The app approves every request
//! in its own window before answering; the model behind an MCP client never
//! sees this channel directly.

use std::path::PathBuf;
use std::time::Duration;

use interprocess::local_socket::tokio::{prelude::*, Stream};
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, Name};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const PROTOCOL_VERSION: u32 = 1;
pub const APP_IDENTIFIER: &str = "com.cwksolutions.keyfold";
/// How long a client waits for the user to approve.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    /// Self-reported, e.g. "keyfold-cli" or "keyfold-mcp (Cursor)".
    pub name: String,
    pub pid: u32,
    #[serde(default)]
    pub exe: Option<String>,
}

impl ClientInfo {
    pub fn current(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pid: std::process::id(),
            exe: std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Op {
    /// Project and environment names.
    Projects,
    /// Secret names in one environment, never values.
    SecretNames {
        project: String,
        environment: String,
    },
    /// All key/value pairs of one environment, for the local client to write or inject.
    Env {
        project: String,
        environment: String,
    },
    /// Add or update one secret.
    Store {
        project: String,
        environment: String,
        key: String,
        value: String,
    },
    /// Create a project (idempotent) with the given environments (defaults to development + production).
    CreateProject {
        name: String,
        environments: Vec<String>,
    },
    /// Add or update many secrets at once, e.g. from a .env file. `create` makes a missing project or environment.
    ImportEnv {
        project: String,
        environment: String,
        entries: Vec<(String, String)>,
        create: bool,
    },
}

impl Op {
    pub fn project(&self) -> Option<&str> {
        match self {
            Op::Projects | Op::CreateProject { .. } => None,
            Op::SecretNames { project, .. }
            | Op::Env { project, .. }
            | Op::Store { project, .. }
            | Op::ImportEnv { project, .. } => Some(project),
        }
    }
    pub fn environment(&self) -> Option<&str> {
        match self {
            Op::Projects | Op::CreateProject { .. } => None,
            Op::SecretNames { environment, .. }
            | Op::Env { environment, .. }
            | Op::Store { environment, .. }
            | Op::ImportEnv { environment, .. } => Some(environment),
        }
    }
    /// Human sentence for the approval sheet.
    pub fn describe(&self) -> String {
        match self {
            Op::Projects => "list your project and environment names".into(),
            Op::SecretNames {
                project,
                environment,
            } => format!("list the secret names in {project} / {environment}"),
            Op::Env {
                project,
                environment,
            } => format!("read every secret in {project} / {environment}"),
            Op::Store {
                project,
                environment,
                key,
                ..
            } => format!("store {key} in {project} / {environment}"),
            Op::CreateProject { name, environments } => {
                if environments.is_empty() {
                    format!("create the project {name}")
                } else {
                    format!(
                        "create the project {name} with environments {}",
                        environments.join(", ")
                    )
                }
            }
            Op::ImportEnv {
                project,
                environment,
                entries,
                ..
            } => {
                format!(
                    "import {} secrets into {project} / {environment}",
                    entries.len()
                )
            }
        }
    }
    /// Reads of values are the sensitive ones.
    pub fn reads_values(&self) -> bool {
        matches!(self, Op::Env { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    pub v: u32,
    pub id: String,
    pub client: ClientInfo,
    pub op: Op,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EnvInfo {
    pub name: String,
    pub secret_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProjectInfo {
    pub name: String,
    pub environments: Vec<EnvInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Projects {
        projects: Vec<ProjectInfo>,
    },
    SecretNames {
        names: Vec<String>,
    },
    Env {
        entries: Vec<(String, String)>,
    },
    Stored {
        created: bool,
    },
    ProjectCreated {
        created: bool,
        environments: Vec<String>,
    },
    Imported {
        added: usize,
        updated: usize,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AgentError {
    /// locked | denied | timeout | not_found | not_running | protocol | internal
    pub code: String,
    pub message: String,
}

impl AgentError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AgentError {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Reply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentError>,
}

impl Response {
    pub fn ok(id: &str, result: Reply) -> Self {
        Self {
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }
    pub fn err(id: &str, error: AgentError) -> Self {
        Self {
            id: id.into(),
            ok: false,
            result: None,
            error: Some(error),
        }
    }
}

/// Where the app listens. Unix: a socket file in the app's data directory
/// (mode 0600), falling back to /tmp when the path would exceed the OS limit.
/// Windows: a named pipe.
pub fn socket_path() -> PathBuf {
    if cfg!(windows) {
        return PathBuf::from(format!("{APP_IDENTIFIER}.agent"));
    }
    let preferred = dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_IDENTIFIER)
        .join("agent.sock");
    if preferred.as_os_str().len() < 100 {
        preferred
    } else {
        let uid = std::env::var("UID").unwrap_or_else(|_| "user".into());
        PathBuf::from(format!("/tmp/keyfold-{uid}.sock"))
    }
}

pub fn socket_name() -> std::io::Result<Name<'static>> {
    let path = socket_path();
    if cfg!(windows) {
        path.to_string_lossy()
            .into_owned()
            .to_ns_name::<GenericNamespaced>()
    } else {
        path.to_fs_name::<GenericFilePath>()
    }
}

/// Send one request to the running app and wait for its answer.
pub async fn call(client: ClientInfo, op: Op) -> Result<Reply, AgentError> {
    let name = socket_name().map_err(|e| AgentError::new("internal", e.to_string()))?;
    let stream = Stream::connect(name).await.map_err(|_| {
        AgentError::new(
            "not_running",
            "Keyfold is not running. Open the app and try again.",
        )
    })?;
    let (recv, mut send) = stream.split();
    let req = Request {
        v: PROTOCOL_VERSION,
        id: uuid::Uuid::new_v4().to_string(),
        client,
        op,
    };
    let mut line =
        serde_json::to_string(&req).map_err(|e| AgentError::new("internal", e.to_string()))?;
    line.push('\n');
    send.write_all(line.as_bytes())
        .await
        .map_err(|e| AgentError::new("internal", e.to_string()))?;
    let mut reader = BufReader::new(recv);
    let mut buf = String::new();
    let read = tokio::time::timeout(
        APPROVAL_TIMEOUT + Duration::from_secs(5),
        reader.read_line(&mut buf),
    )
    .await
    .map_err(|_| AgentError::new("timeout", "Keyfold did not answer in time."))?
    .map_err(|e| AgentError::new("internal", e.to_string()))?;
    if read == 0 {
        return Err(AgentError::new(
            "protocol",
            "Keyfold closed the connection.",
        ));
    }
    let resp: Response =
        serde_json::from_str(buf.trim()).map_err(|e| AgentError::new("protocol", e.to_string()))?;
    if resp.ok {
        resp.result
            .ok_or_else(|| AgentError::new("protocol", "empty reply"))
    } else {
        Err(resp
            .error
            .unwrap_or_else(|| AgentError::new("internal", "unknown error")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_describe_and_roundtrip() {
        let op = Op::Env {
            project: "Acme".into(),
            environment: "production".into(),
        };
        assert!(op.reads_values());
        assert_eq!(op.describe(), "read every secret in Acme / production");
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"type\":\"env\""));
        assert_eq!(serde_json::from_str::<Op>(&json).unwrap(), op);
        assert!(!Op::Projects.reads_values());
        assert_eq!(Op::Projects.project(), None);
    }

    #[test]
    fn socket_path_is_short_enough_on_unix() {
        let p = socket_path();
        if !cfg!(windows) {
            assert!(p.as_os_str().len() < 104, "{p:?}");
        }
    }
}
