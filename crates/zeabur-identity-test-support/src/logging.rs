//! Per-scenario native JSON tracing capture for tests, without a global subscriber.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;

/// A value of an event field in the native JSON log format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// A string field.
    Text(String),
    /// A boolean field.
    Flag(bool),
    /// An integer field.
    Count(i64),
}

impl FieldValue {
    /// The string value, if this is a string field.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Flag(_) | Self::Count(_) => None,
        }
    }
}

impl PartialEq<&str> for FieldValue {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

/// One record of the native JSON log format.
///
/// `extra` holds any other top-level member, so a test can assert that `span` and `spans` are
/// absent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    /// The event target.
    pub target: String,
    /// The event fields.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldValue>,
    /// The other top-level members.
    #[serde(flatten)]
    pub extra: BTreeMap<String, FieldValue>,
}

impl Record {
    /// A string field, if it is present and a string.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).and_then(FieldValue::as_str)
    }

    /// The target and every field value as text, for searching a log for a leaked secret.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = self.target.clone();
        for value in self.fields.values().chain(self.extra.values()) {
            text.push('\n');
            match value {
                FieldValue::Text(value) => text.push_str(value),
                FieldValue::Flag(value) => text.push_str(&value.to_string()),
                FieldValue::Count(value) => text.push_str(&value.to_string()),
            }
        }
        text
    }
}

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
    pub fn records(&self) -> Vec<Record> {
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
        assert_eq!(records[0].target, "zeabur_identity::audit");
        assert!(!records[0].extra.contains_key("span"));
        assert!(!records[0].extra.contains_key("spans"));
        assert!(!format!("{records:?}").contains("secret-span-token-sentinel"));
    }
}
