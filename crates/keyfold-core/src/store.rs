//! In-memory edits on a `VaultBody`, with free-plan limits enforced here so
//! every front end (desktop app, CLI) gets the same rules.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Limit, Result};
use crate::model::*;
use crate::time::now_ms;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Free,
    Pro,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_projects: Option<usize>,
    pub max_items: Option<usize>,
}

pub const FREE_MAX_PROJECTS: usize = 1;
pub const FREE_MAX_ITEMS: usize = 25;

impl Plan {
    pub fn limits(self) -> Limits {
        match self {
            Plan::Free => Limits {
                max_projects: Some(FREE_MAX_PROJECTS),
                max_items: Some(FREE_MAX_ITEMS),
            },
            Plan::Pro => Limits {
                max_projects: None,
                max_items: None,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretInput {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct PasswordInput {
    pub title: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn clean(s: &str) -> String {
    s.trim().to_string()
}

impl VaultBody {
    pub fn secret_count(&self) -> usize {
        self.projects
            .iter()
            .flat_map(|p| p.environments.iter())
            .map(|e| e.secrets.len())
            .sum()
    }

    /// Secrets plus passwords: the number the free plan counts.
    pub fn item_count(&self) -> usize {
        self.secret_count() + self.passwords.len()
    }

    fn ensure_can_add_project(&self, plan: Plan) -> Result<()> {
        if let Some(max) = plan.limits().max_projects {
            if self.projects.len() >= max {
                return Err(Error::LimitReached(Limit::Projects(max)));
            }
        }
        Ok(())
    }

    fn ensure_can_add_item(&self, plan: Plan) -> Result<()> {
        if let Some(max) = plan.limits().max_items {
            if self.item_count() >= max {
                return Err(Error::LimitReached(Limit::Items(max)));
            }
        }
        Ok(())
    }

    // ----- projects -----

    pub fn add_project(&mut self, name: &str, color: &str, plan: Plan) -> Result<String> {
        self.ensure_can_add_project(plan)?;
        let name = clean(name);
        if name.is_empty() {
            return Err(Error::InvalidFormat("project name is empty"));
        }
        let now = now_ms();
        let id = new_id();
        self.projects.push(Project {
            id: id.clone(),
            name,
            color: color.to_string(),
            created_at: now,
            updated_at: now,
            environments: Vec::new(),
        });
        Ok(id)
    }

    pub fn project_mut(&mut self, id: &str) -> Result<&mut Project> {
        self.projects
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Error::NotFound)
    }

    pub fn project(&self, id: &str) -> Result<&Project> {
        self.projects
            .iter()
            .find(|p| p.id == id)
            .ok_or(Error::NotFound)
    }

    pub fn update_project(&mut self, id: &str, name: &str, color: &str) -> Result<()> {
        let name = clean(name);
        if name.is_empty() {
            return Err(Error::InvalidFormat("project name is empty"));
        }
        let p = self.project_mut(id)?;
        p.name = name;
        p.color = color.to_string();
        p.updated_at = now_ms();
        Ok(())
    }

    pub fn delete_project(&mut self, id: &str) -> Result<()> {
        let before = self.projects.len();
        self.projects.retain(|p| p.id != id);
        if self.projects.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    // ----- environments -----

    pub fn add_environment(&mut self, project_id: &str, name: &str) -> Result<String> {
        let name = clean(name);
        if name.is_empty() {
            return Err(Error::InvalidFormat("environment name is empty"));
        }
        let p = self.project_mut(project_id)?;
        let id = new_id();
        let order = p.environments.len() as u32;
        p.environments.push(Environment {
            id: id.clone(),
            name,
            order,
            secrets: Vec::new(),
        });
        p.updated_at = now_ms();
        Ok(id)
    }

    pub fn rename_environment(&mut self, env_id: &str, name: &str) -> Result<()> {
        let name = clean(name);
        if name.is_empty() {
            return Err(Error::InvalidFormat("environment name is empty"));
        }
        let (pi, ei) = self.env_index(env_id)?;
        let p = &mut self.projects[pi];
        p.environments[ei].name = name;
        p.updated_at = now_ms();
        Ok(())
    }

    pub fn delete_environment(&mut self, env_id: &str) -> Result<()> {
        for p in &mut self.projects {
            let before = p.environments.len();
            p.environments.retain(|e| e.id != env_id);
            if p.environments.len() != before {
                p.updated_at = now_ms();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// (project index, environment index) for an environment id.
    fn env_index(&self, env_id: &str) -> Result<(usize, usize)> {
        for (pi, p) in self.projects.iter().enumerate() {
            if let Some(ei) = p.environments.iter().position(|e| e.id == env_id) {
                return Ok((pi, ei));
            }
        }
        Err(Error::NotFound)
    }

    // ----- secrets -----

    pub fn add_secret(&mut self, env_id: &str, input: SecretInput, plan: Plan) -> Result<String> {
        self.ensure_can_add_item(plan)?;
        let key = clean(&input.key);
        if key.is_empty() {
            return Err(Error::InvalidFormat("secret name is empty"));
        }
        let now = now_ms();
        let id = new_id();
        let (pi, ei) = self.env_index(env_id)?;
        let p = &mut self.projects[pi];
        p.environments[ei].secrets.push(Secret {
            id: id.clone(),
            key,
            value: input.value.clone(),
            notes: input.notes.clone(),
            tags: input.tags.clone(),
            url: input.url.clone(),
            expires_at: input.expires_at,
            created_at: now,
            updated_at: now,
        });
        p.updated_at = now;
        Ok(id)
    }

    pub fn update_secret(&mut self, secret_id: &str, input: SecretInput) -> Result<()> {
        let key = clean(&input.key);
        if key.is_empty() {
            return Err(Error::InvalidFormat("secret name is empty"));
        }
        let now = now_ms();
        for p in &mut self.projects {
            for e in &mut p.environments {
                if let Some(s) = e.secrets.iter_mut().find(|s| s.id == secret_id) {
                    s.key = key;
                    s.value = input.value.clone();
                    s.notes = input.notes.clone();
                    s.tags = input.tags.clone();
                    s.url = input.url.clone();
                    s.expires_at = input.expires_at;
                    s.updated_at = now;
                    p.updated_at = now;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    pub fn delete_secret(&mut self, secret_id: &str) -> Result<()> {
        for p in &mut self.projects {
            for e in &mut p.environments {
                let before = e.secrets.len();
                e.secrets.retain(|s| s.id != secret_id);
                if e.secrets.len() != before {
                    p.updated_at = now_ms();
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    pub fn find_secret(&self, secret_id: &str) -> Option<(&Project, &Environment, &Secret)> {
        for p in &self.projects {
            for e in &p.environments {
                if let Some(s) = e.secrets.iter().find(|s| s.id == secret_id) {
                    return Some((p, e, s));
                }
            }
        }
        None
    }

    // ----- passwords -----

    pub fn add_password(&mut self, input: PasswordInput, plan: Plan) -> Result<String> {
        self.ensure_can_add_item(plan)?;
        let title = clean(&input.title);
        if title.is_empty() {
            return Err(Error::InvalidFormat("title is empty"));
        }
        let now = now_ms();
        let id = new_id();
        self.passwords.push(PasswordEntry {
            id: id.clone(),
            title,
            username: input.username.clone(),
            password: input.password.clone(),
            url: input.url.clone(),
            notes: input.notes.clone(),
            totp_secret: input.totp_secret.clone(),
            tags: input.tags.clone(),
            created_at: now,
            updated_at: now,
        });
        Ok(id)
    }

    pub fn update_password(&mut self, id: &str, input: PasswordInput) -> Result<()> {
        let title = clean(&input.title);
        if title.is_empty() {
            return Err(Error::InvalidFormat("title is empty"));
        }
        let e = self
            .passwords
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Error::NotFound)?;
        e.title = title;
        e.username = input.username.clone();
        e.password = input.password.clone();
        e.url = input.url.clone();
        e.notes = input.notes.clone();
        // None keeps the stored 2FA secret, Some("") removes it, Some(x) replaces it.
        match input.totp_secret.as_deref() {
            None => {}
            Some("") => e.totp_secret = None,
            Some(t) => e.totp_secret = Some(t.to_string()),
        }
        e.tags = input.tags.clone();
        e.updated_at = now_ms();
        Ok(())
    }

    pub fn delete_password(&mut self, id: &str) -> Result<()> {
        let before = self.passwords.len();
        self.passwords.retain(|p| p.id != id);
        if self.passwords.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub fn find_password(&self, id: &str) -> Option<&PasswordEntry> {
        self.passwords.iter().find(|p| p.id == id)
    }
}
