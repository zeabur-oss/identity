//! Per-scenario native JSON tracing capture for tests, without a global subscriber.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

/// An in-memory writer shared by a scenario's subscriber and assertions.
#[derive(Clone, Debug, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Creates an empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a subscriber to attach to the complete scenario future with `with_subscriber`.
    ///
    /// Spans are intentionally omitted, matching the server's JSON formatter.
    #[must_use]
    pub fn dispatch(&self) -> Dispatch {
        Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .with_ansi(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(self.clone())
                .finish(),
        )
    }

    /// Reads complete native JSON records emitted so far.
    ///
    /// # Panics
    ///
    /// Panics if a completed record is not JSON; malformed logging must fail the test rather
    /// than disappear from its assertions. Call after the scenario future completes.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "the test helper must reject malformed formatter output"
    )]
    pub fn records(&self) -> Vec<Value> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("tracing record must be JSON"))
            .collect()
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Capture;

    #[test]
    fn json_omits_secret_bearing_spans() {
        let capture = Capture::new();
        tracing::dispatcher::with_default(&capture.dispatch(), || {
            let span = tracing::info_span!("request", token = "secret-span-token-sentinel");
            let _entered = span.enter();
            tracing::info!(target: "zeabur_identity::audit", event = "oauth.code_exchange", outcome = "success");
        });
        let records = capture.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["target"], "zeabur_identity::audit");
        assert!(!crate::has_member(&records[0], "span"));
        assert!(!crate::has_member(&records[0], "spans"));
        assert!(
            !serde_json::to_string(&records)
                .unwrap()
                .contains("secret-span-token-sentinel")
        );
    }
}
