//! The `zeabur_identity::audit` records of sign-in, enrolment, linking and account changes. The
//! fields are listed in `crates/zeabur-identity/README.md`.

use zeabur_identity_store::User;

use crate::account::Audit;

/// One audit self. A field left `None` is not logged.
#[derive(Default)]
pub(crate) struct Record<'a> {
    pub(crate) event: &'static str,
    /// The message when the operation succeeded, then when it failed.
    pub(crate) messages: [&'static str; 2],
    pub(crate) phase: Option<&'static str>,
    pub(crate) method: Option<&'static str>,
    pub(crate) provider: Option<&'a str>,
    /// The verified user's name.
    pub(crate) user: Option<&'a str>,
    /// The same, for account page events.
    pub(crate) actor: Option<&'a str>,
    pub(crate) subject: Option<&'a str>,
    /// What an account page change touched, and who asked.
    pub(crate) change: Option<&'a Audit<'a>>,
}

impl<'a> Record<'a> {
    /// An account page event by `user`.
    pub(crate) fn account(
        event: &'static str,
        user: Option<&'a User>,
        change: &'a Audit<'a>,
    ) -> Self {
        Self {
            event,
            messages: ["account changed", "account change failed"],
            actor: user.map(|u| u.name.as_str()),
            subject: user.map(|u| u.subject.as_str()),
            change: Some(change),
            ..Self::default()
        }
    }

    /// Logs it as a success, or as a failure for `reason`.
    pub(crate) fn log(&self, reason: Option<&str>) {
        let change = self.change;
        let requester = change.and_then(|c| c.requester);
        let client_ip = requester.and_then(|r| r.ip).map(|ip| ip.to_string());
        let peer = requester.and_then(|r| r.peer).map(|ip| ip.to_string());
        let user_agent = requester.and_then(|r| r.user_agent.as_deref());
        let credential = change.and_then(|c| c.credential.as_deref());
        let session = change.and_then(|c| c.session.as_deref());
        let [done, failed] = self.messages;
        match reason {
            None => tracing::info!(
                target: "zeabur_identity::audit",
                event = self.event,
                outcome = "success",
                phase = self.phase,
                method = self.method,
                provider = self.provider,
                user = self.user,
                actor = self.actor,
                subject = self.subject,
                credential,
                aaguid = change.and_then(|c| c.aaguid.as_deref()),
                session,
                revoked = change.map(|c| c.revoked),
                client_ip = client_ip.as_deref(),
                peer = peer.as_deref(),
                user_agent,
                "{done}"
            ),
            Some(reason) => tracing::warn!(
                target: "zeabur_identity::audit",
                event = self.event,
                outcome = "failure",
                phase = self.phase,
                method = self.method,
                provider = self.provider,
                reason,
                user = self.user,
                actor = self.actor,
                subject = self.subject,
                credential,
                session,
                client_ip = client_ip.as_deref(),
                peer = peer.as_deref(),
                user_agent,
                "{failed}"
            ),
        }
    }
}
