//! `keyfold` command line. Every subcommand asks the running Keyfold app over
//! the local socket, and the app asks the user before answering.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use keyfold_agent::{call, ClientInfo, Op, Reply};

#[derive(Parser)]
#[command(
    name = "keyfold",
    version,
    about = "Keyfold: offline secrets vault, command line"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List projects and environments
    Projects,
    /// List secret names in an environment (never values)
    Names {
        #[arg(short, long)]
        project: String,
        #[arg(short, long)]
        environment: String,
    },
    /// Write an environment to a .env file (or print with --stdout)
    Env {
        #[arg(short, long)]
        project: String,
        #[arg(short, long)]
        environment: String,
        /// Output file, default .env in the current directory
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Print to the terminal instead of writing a file
        #[arg(long)]
        stdout: bool,
    },
    /// Run a command with the environment's secrets injected as variables
    Run {
        #[arg(short, long)]
        project: String,
        #[arg(short, long)]
        environment: String,
        /// The command and its arguments, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Create a project (default environments: development, production)
    CreateProject {
        name: String,
        /// Environment names, repeatable
        #[arg(short, long = "env")]
        environments: Vec<String>,
    },
    /// Import a .env file into an environment (creates project and environment if missing)
    Import {
        #[arg(short, long)]
        project: String,
        #[arg(short, long)]
        environment: String,
        /// The .env file, default ./.env
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Start the MCP server on stdin/stdout (for Cursor, Claude Code, etc.)
    Mcp,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let me = ClientInfo::current("keyfold-cli");
    match cli.cmd {
        Cmd::Projects => {
            let Reply::Projects { projects } = call(me, Op::Projects).await? else {
                bail!("unexpected reply")
            };
            if projects.is_empty() {
                println!("No projects yet.");
            }
            for p in projects {
                println!("{}", p.name);
                for e in p.environments {
                    println!("  {}  ({} secrets)", e.name, e.secret_count);
                }
            }
        }
        Cmd::Names {
            project,
            environment,
        } => {
            let Reply::SecretNames { names } = call(
                me,
                Op::SecretNames {
                    project,
                    environment,
                },
            )
            .await?
            else {
                bail!("unexpected reply")
            };
            for n in names {
                println!("{n}");
            }
        }
        Cmd::Env {
            project,
            environment,
            out,
            stdout,
        } => {
            let Reply::Env { entries } = call(
                me,
                Op::Env {
                    project: project.clone(),
                    environment: environment.clone(),
                },
            )
            .await?
            else {
                bail!("unexpected reply")
            };
            let text = keyfold_core::envfile::render_env(
                entries.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            );
            if stdout {
                print!("{text}");
            } else {
                let path = out.unwrap_or_else(|| PathBuf::from(".env"));
                std::fs::write(&path, text)
                    .with_context(|| format!("writing {}", path.display()))?;
                eprintln!(
                    "wrote {} secrets from {project} / {environment} to {}",
                    entries.len(),
                    path.display()
                );
            }
        }
        Cmd::Run {
            project,
            environment,
            command,
        } => {
            let Reply::Env { entries } = call(
                me,
                Op::Env {
                    project,
                    environment,
                },
            )
            .await?
            else {
                bail!("unexpected reply")
            };
            let (prog, args) = command.split_first().context("no command given")?;
            let status = tokio::process::Command::new(prog)
                .args(args)
                .envs(entries.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await
                .with_context(|| format!("running {prog}"))?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Cmd::CreateProject { name, environments } => {
            let Reply::ProjectCreated {
                created,
                environments,
            } = call(
                me,
                Op::CreateProject {
                    name: name.clone(),
                    environments,
                },
            )
            .await?
            else {
                bail!("unexpected reply")
            };
            eprintln!(
                "{} {name} with environments: {}",
                if created {
                    "created"
                } else {
                    "already exists:"
                },
                environments.join(", ")
            );
        }
        Cmd::Import {
            project,
            environment,
            file,
        } => {
            let path = file.unwrap_or_else(|| PathBuf::from(".env"));
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let entries = keyfold_core::envfile::parse_env(&text);
            if entries.is_empty() {
                bail!("{} contains no KEY=VALUE lines", path.display());
            }
            let count = entries.len();
            let Reply::Imported { added, updated } = call(
                me,
                Op::ImportEnv {
                    project: project.clone(),
                    environment: environment.clone(),
                    entries,
                    create: true,
                },
            )
            .await?
            else {
                bail!("unexpected reply")
            };
            eprintln!("imported {count} keys into {project} / {environment}: {added} added, {updated} updated");
        }
        Cmd::Mcp => mcp::serve().await?,
    }
    Ok(())
}

mod mcp;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cmd, clap::Error> {
        Cli::try_parse_from(std::iter::once("keyfold").chain(args.iter().copied())).map(|c| c.cmd)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_takes_the_command_after_double_dash() {
        let Cmd::Run {
            project,
            environment,
            command,
        } = parse(&[
            "run", "-p", "Acme", "-e", "dev", "--", "npm", "test", "--watch",
        ])
        .unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!((project.as_str(), environment.as_str()), ("Acme", "dev"));
        assert_eq!(command, ["npm", "test", "--watch"]);
        assert!(parse(&["run", "-p", "Acme", "-e", "dev"]).is_err());
    }

    #[test]
    fn env_defaults_and_flags() {
        let Cmd::Env { out, stdout, .. } =
            parse(&["env", "--project", "Acme", "--environment", "prod"]).unwrap()
        else {
            panic!("expected env")
        };
        assert_eq!((out, stdout), (None, false));
        let Cmd::Env { out, stdout, .. } =
            parse(&["env", "-p", "Acme", "-e", "prod", "-o", "x.env", "--stdout"]).unwrap()
        else {
            panic!("expected env")
        };
        assert_eq!((out, stdout), (Some(PathBuf::from("x.env")), true));
        assert!(parse(&["env", "-p", "Acme"]).is_err());
    }

    #[test]
    fn create_project_collects_repeated_envs() {
        let Cmd::CreateProject { name, environments } =
            parse(&["create-project", "Acme", "--env", "dev", "-e", "staging"]).unwrap()
        else {
            panic!("expected create-project")
        };
        assert_eq!(name, "Acme");
        assert_eq!(environments, ["dev", "staging"]);
    }
}
