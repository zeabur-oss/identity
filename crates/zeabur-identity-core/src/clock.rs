//! Wall-clock time in whole seconds since the Unix epoch.
//!
//! Everything that depends on the current time takes a [`Clock`], so tests can drive time
//! explicitly.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A point in time, in whole seconds since the Unix epoch.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct UnixTime(u64);

impl UnixTime {
    /// Creates a time from seconds since the Unix epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Returns the seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Returns `self + duration`, saturating at the maximum representable time.
    #[must_use]
    pub const fn saturating_add(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.as_secs()))
    }

    /// Returns `self - duration`, saturating at the epoch.
    #[must_use]
    pub const fn saturating_sub(self, duration: Duration) -> Self {
        Self(self.0.saturating_sub(duration.as_secs()))
    }
}

/// A source of the current time.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current time.
    fn now(&self) -> UnixTime;
}

/// A shared clock is a clock.
impl<C: Clock> Clock for std::sync::Arc<C> {
    fn now(&self) -> UnixTime {
        C::now(self)
    }
}

/// The system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTime {
        // A clock set before 1970 is a broken host; report the epoch rather than panic.
        UnixTime(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates() {
        let max = UnixTime::from_secs(u64::MAX);
        assert_eq!(max.saturating_add(Duration::from_secs(1)), max);
        assert_eq!(
            UnixTime::from_secs(1).saturating_sub(Duration::from_secs(5)),
            UnixTime::from_secs(0)
        );
    }
}
