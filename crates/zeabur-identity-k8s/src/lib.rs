#![doc = include_str!("../README.md")]

pub mod clients;
pub mod credentials;
pub mod deployment;
pub mod directory;
pub mod gc;
pub mod grants;
pub mod internal_tls;
pub mod invitations;
pub mod keys;
pub mod kube_config;
pub mod objects;
pub mod rbac;
pub mod setup;
pub mod upstream;
pub mod users;
pub mod watch;

/// Label set on every object Zeabur Identity creates.
pub const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "zeabur-identity");

/// Default name of the Secret holding signing keys.
pub const KEY_SECRET: &str = "zeabur-identity-signing-keys";
