//! MCP server over stdio for Cursor, Claude Code and other agents.
//! Design rule: secret values never appear in a tool result. Tools write files
//! or run commands on the agent's behalf; the user approves each request in
//! the Keyfold window.

use std::process::Stdio;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
};

use keyfold_agent::{call, AgentError, ClientInfo, Op, Reply};

#[derive(Clone)]
pub struct Keyfold {
    tool_router: ToolRouter<Keyfold>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvRef {
    #[schemars(description = "Project name exactly as shown in Keyfold (case-insensitive)")]
    pub project: String,
    #[schemars(description = "Environment name, for example development, staging or production")]
    pub environment: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct WriteEnvParams {
    pub project: String,
    pub environment: String,
    #[schemars(
        description = "Path of the .env file to write, absolute or relative to the working directory"
    )]
    pub path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RunParams {
    pub project: String,
    pub environment: String,
    #[schemars(
        description = "Shell command to run; the environment's secrets are injected as environment variables"
    )]
    pub command: String,
    #[schemars(description = "Working directory for the command (optional)")]
    pub cwd: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateProjectParams {
    #[schemars(description = "Project name, e.g. the repository or product name")]
    pub name: String,
    #[schemars(
        description = "Environment names to create; defaults to development and production"
    )]
    pub environments: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ImportEnvParams {
    pub project: String,
    pub environment: String,
    #[schemars(
        description = "Path of a .env file to import, absolute or relative to the working directory. The file is read by the Keyfold MCP process; its values are not returned to you"
    )]
    pub path: String,
    #[schemars(
        description = "Create the project and environment if they do not exist (default true)"
    )]
    pub create_missing: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StoreParams {
    pub project: String,
    pub environment: String,
    #[schemars(description = "Secret name in ENV_VAR style, e.g. OPENAI_API_KEY")]
    pub key: String,
    pub value: String,
}

fn client() -> ClientInfo {
    ClientInfo::current("keyfold-mcp")
}

fn text(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s.into())])
}

/// User-facing failures come back as tool errors the model can read and relay.
fn failure(e: AgentError) -> CallToolResult {
    let msg = match e.code.as_str() {
        "denied" => "The user denied this request in Keyfold.".to_string(),
        "locked" => "Keyfold is locked. Ask the user to unlock it, then try again.".to_string(),
        "not_running" => "Keyfold is not running. Ask the user to open the app.".to_string(),
        "timeout" => "Keyfold showed an approval prompt but nobody answered in time.".to_string(),
        _ => e.message,
    };
    CallToolResult::error(vec![ContentBlock::text(msg)])
}

const MAX_OUTPUT: usize = 20_000;

fn clip(s: String) -> String {
    if s.len() <= MAX_OUTPUT {
        s
    } else {
        let cut = s.floor_char_boundary(MAX_OUTPUT);
        format!("{}\n… [truncated {} bytes]", &s[..cut], s.len() - cut)
    }
}

#[tool_router]
impl Keyfold {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List the user's Keyfold projects and their environments with secret counts. Names only."
    )]
    async fn keyfold_projects(&self) -> Result<CallToolResult, McpError> {
        match call(client(), Op::Projects).await {
            Ok(Reply::Projects { projects }) => {
                if projects.is_empty() {
                    return Ok(text("No projects in Keyfold yet."));
                }
                let mut out = String::new();
                for p in projects {
                    out.push_str(&format!("{}\n", p.name));
                    for e in p.environments {
                        out.push_str(&format!("  - {} ({} secrets)\n", e.name, e.secret_count));
                    }
                }
                Ok(text(out))
            }
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }

    #[tool(
        description = "List the secret names in one project environment. Values are never returned."
    )]
    async fn keyfold_secret_names(
        &self,
        Parameters(p): Parameters<EnvRef>,
    ) -> Result<CallToolResult, McpError> {
        match call(
            client(),
            Op::SecretNames {
                project: p.project,
                environment: p.environment,
            },
        )
        .await
        {
            Ok(Reply::SecretNames { names }) => Ok(text(if names.is_empty() {
                "No secrets in that environment.".to_string()
            } else {
                names.join("\n")
            })),
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }

    #[tool(
        description = "Write a .env file containing every secret of a project environment to the given path. The user approves in Keyfold. Returns the number of keys written; the values themselves are never returned to you."
    )]
    async fn keyfold_write_env(
        &self,
        Parameters(p): Parameters<WriteEnvParams>,
    ) -> Result<CallToolResult, McpError> {
        match call(
            client(),
            Op::Env {
                project: p.project.clone(),
                environment: p.environment.clone(),
            },
        )
        .await
        {
            Ok(Reply::Env { entries }) => {
                let body = keyfold_core::envfile::render_env(
                    entries.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                );
                match std::fs::write(&p.path, body) {
                    Ok(()) => Ok(text(format!(
                        "Wrote {} keys from {} / {} to {}. Add that file to .gitignore.",
                        entries.len(),
                        p.project,
                        p.environment,
                        p.path
                    ))),
                    Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "Could not write {}: {e}",
                        p.path
                    ))])),
                }
            }
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }

    #[tool(
        description = "Run a shell command with the environment's secrets injected as environment variables (for example `npm test` or `python deploy.py`). The user approves in Keyfold. Returns the exit code and output; secret values only appear if the command prints them."
    )]
    async fn keyfold_run(
        &self,
        Parameters(p): Parameters<RunParams>,
    ) -> Result<CallToolResult, McpError> {
        let entries = match call(
            client(),
            Op::Env {
                project: p.project,
                environment: p.environment,
            },
        )
        .await
        {
            Ok(Reply::Env { entries }) => entries,
            Ok(_) => return Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => return Ok(failure(e)),
        };
        let (shell, flag) = if cfg!(windows) {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };
        let mut cmd = tokio::process::Command::new(shell);
        cmd.arg(flag)
            .arg(&p.command)
            .envs(entries.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &p.cwd {
            cmd.current_dir(cwd);
        }
        match cmd.output().await {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                let stdout = clip(String::from_utf8_lossy(&out.stdout).into_owned());
                let stderr = clip(String::from_utf8_lossy(&out.stderr).into_owned());
                let report = format!(
                    "exit code: {code}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
                );
                Ok(if out.status.success() {
                    text(report)
                } else {
                    CallToolResult::error(vec![ContentBlock::text(report)])
                })
            }
            Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "Could not start the command: {e}"
            ))])),
        }
    }

    #[tool(
        description = "Store or update one secret in a project environment, for example a key you just generated or the user pasted. The user approves in Keyfold."
    )]
    async fn keyfold_store(
        &self,
        Parameters(p): Parameters<StoreParams>,
    ) -> Result<CallToolResult, McpError> {
        match call(
            client(),
            Op::Store {
                project: p.project.clone(),
                environment: p.environment.clone(),
                key: p.key.clone(),
                value: p.value,
            },
        )
        .await
        {
            Ok(Reply::Stored { created }) => Ok(text(format!(
                "{} {} in {} / {}.",
                if created { "Stored" } else { "Updated" },
                p.key,
                p.project,
                p.environment
            ))),
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }
    #[tool(
        description = "Create a Keyfold project with environments (default: development and production). Safe to call twice; an existing project is left as is."
    )]
    async fn keyfold_create_project(
        &self,
        Parameters(p): Parameters<CreateProjectParams>,
    ) -> Result<CallToolResult, McpError> {
        match call(
            client(),
            Op::CreateProject {
                name: p.name.clone(),
                environments: p.environments.unwrap_or_default(),
            },
        )
        .await
        {
            Ok(Reply::ProjectCreated {
                created,
                environments,
            }) => Ok(text(format!(
                "{} project {} with environments: {}.",
                if created { "Created" } else { "Found existing" },
                p.name,
                environments.join(", ")
            ))),
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }

    #[tool(
        description = "Import every KEY=VALUE pair from a .env file into a project environment. Existing keys are updated. The user approves in Keyfold; you receive counts, never the values."
    )]
    async fn keyfold_import_env(
        &self,
        Parameters(p): Parameters<ImportEnvParams>,
    ) -> Result<CallToolResult, McpError> {
        let text_content = match std::fs::read_to_string(&p.path) {
            Ok(t) => t,
            Err(e) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "Could not read {}: {e}",
                    p.path
                ))]))
            }
        };
        let entries = keyfold_core::envfile::parse_env(&text_content);
        if entries.is_empty() {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "{} contains no KEY=VALUE lines.",
                p.path
            ))]));
        }
        let count = entries.len();
        match call(client(), Op::ImportEnv { project: p.project.clone(), environment: p.environment.clone(), entries, create: p.create_missing.unwrap_or(true) }).await {
            Ok(Reply::Imported { added, updated }) => Ok(text(format!("Imported {count} keys from {} into {} / {}: {added} added, {updated} updated. Consider deleting the plain-text file and adding it to .gitignore.", p.path, p.project, p.environment))),
            Ok(_) => Err(McpError::internal_error("unexpected reply", None)),
            Err(e) => Ok(failure(e)),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Keyfold {
    fn get_info(&self) -> ServerConfig {
        let mut info = Implementation::from_build_env();
        info.name = "keyfold".into();
        info.version = env!("CARGO_PKG_VERSION").into();
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(info)
            .with_instructions(
                "Keyfold is the user's offline secrets vault. Use keyfold_projects to discover names, keyfold_write_env or keyfold_run to use secrets without reading them, and keyfold_store to save new ones. Every call is approved by the user inside the Keyfold app; if a call is denied or Keyfold is locked, tell the user and stop."
                    .to_string(),
            )
    }
}

pub async fn serve() -> anyhow::Result<()> {
    let service = Keyfold::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(r: &CallToolResult) -> String {
        serde_json::to_value(r).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn exposes_every_tool_with_a_schema() {
        let mut names: Vec<String> = Keyfold::new()
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "keyfold_create_project",
                "keyfold_import_env",
                "keyfold_projects",
                "keyfold_run",
                "keyfold_secret_names",
                "keyfold_store",
                "keyfold_write_env",
            ]
        );
        let run = Keyfold::new()
            .tool_router
            .list_all()
            .into_iter()
            .find(|t| t.name == "keyfold_run")
            .unwrap();
        let required = serde_json::to_value(&run.input_schema).unwrap()["required"].clone();
        assert_eq!(
            required,
            serde_json::json!(["project", "environment", "command"])
        );
    }

    #[test]
    fn agent_errors_become_readable_tool_errors() {
        for (code, expected) in [
            ("denied", "denied this request"),
            ("locked", "Keyfold is locked"),
            ("not_running", "not running"),
            ("timeout", "nobody answered"),
        ] {
            let r = failure(AgentError::new(code, "raw"));
            assert_eq!(r.is_error, Some(true));
            assert!(message(&r).contains(expected), "{code}");
        }
        assert_eq!(
            message(&failure(AgentError::new("not_found", "no project named x"))),
            "no project named x"
        );
    }

    #[test]
    fn clip_keeps_short_output_and_truncates_on_a_char_boundary() {
        assert_eq!(clip("ok".into()), "ok");
        let long = format!("{}é{}", "a".repeat(MAX_OUTPUT - 1), "b".repeat(100));
        let clipped = clip(long);
        assert!(clipped.starts_with(&"a".repeat(MAX_OUTPUT - 1)));
        assert!(clipped.ends_with("[truncated 102 bytes]"));
    }
}
