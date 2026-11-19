//! The error every storage backend returns, and the retry of a lost compare-and-swap.

use std::fmt::Display;
use std::future::Future;

use thiserror::Error;

/// How many times a read-modify-write is tried before it gives up on a conflict.
pub const WRITE_ATTEMPTS: usize = 4;

/// A storage backend failed, answered ambiguously, or lost every compare-and-swap.
///
/// Callers fail closed: they answer `server_error` and never treat an error as success. A single
/// lost race is not an error; it is an outcome such as `AlreadyExists` or `Replay`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    /// Another writer changed the object since it was read.
    #[error("the stored object changed concurrently")]
    Conflict,
    /// The backend failed or answered ambiguously.
    #[error("storage failed: {0}")]
    Backend(String),
}

impl StoreError {
    /// A backend failure described by `error`.
    pub fn backend(error: impl Display) -> Self {
        Self::Backend(error.to_string())
    }
}

/// Runs `attempt` until it returns `Some`, at most [`WRITE_ATTEMPTS`] times. `attempt` reads,
/// changes and writes; it returns `None` when its write lost to another writer.
///
/// # Errors
///
/// The first error of `attempt`, or [`StoreError::Conflict`] if every attempt lost.
pub async fn retry_on_conflict<T, E, F>(mut attempt: impl FnMut() -> F) -> Result<T, E>
where
    E: From<StoreError>,
    F: Future<Output = Result<Option<T>, E>>,
{
    for _ in 0..WRITE_ATTEMPTS {
        if let Some(done) = attempt().await? {
            return Ok(done);
        }
    }
    Err(StoreError::Conflict.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retries_until_a_write_wins() {
        let mut lost = 0;
        let done = retry_on_conflict(|| {
            lost += 1;
            let won = lost > 1;
            async move { Ok::<_, StoreError>(won.then_some("written")) }
        })
        .await;
        assert_eq!(done, Ok("written"));
    }

    #[tokio::test]
    async fn gives_up_when_every_write_loses() {
        let done = retry_on_conflict(|| async { Ok::<Option<()>, StoreError>(None) }).await;
        assert_eq!(done, Err(StoreError::Conflict));
    }

    #[tokio::test]
    async fn stops_at_the_first_error() {
        let mut tries = 0;
        let done = retry_on_conflict(|| {
            tries += 1;
            async { Err::<Option<()>, _>(StoreError::backend("down")) }
        })
        .await;
        assert_eq!(done, Err(StoreError::Backend("down".to_owned())));
        assert_eq!(tries, 1);
    }
}
