//! One AWS deployment, and the session cache in front of it — R2.C.3.
//!
//! # Why a deployment is not a request
//!
//! The audience, the region and the role ARN are the three things an agent must
//! not be able to name. SigV4 signs the host, the path and a set of headers, so
//! a request that carried its own audience could have the broker sign a call for
//! one destination and send it to another — and the signature would be the only
//! thing in the request that disagreed with where it went. The same reasoning
//! `PostgresConnect` already uses: the deployment declares, the request
//! proposes, and the broker answers with the *declared* entry.
//!
//! The credential id is the one thing the request does name, and it names a
//! *reference*. The broker resolves it against the deployments it was given, so
//! an agent cannot ask for a credential that was never configured — not by
//! phrasing, and not by guessing an id.
//!
//! # Why the binding exists at all
//!
//! Because the cache has to outlive the request. A binding built per call would
//! re-mint a session and re-borrow the long-lived key on every single request,
//! which is precisely what `AwsSecretPort` was written to prevent.

use std::sync::Arc;

use asv_connector_http::SecretPort;
use asv_domain::{Authority, CredentialId};

use crate::aws::client::{AwsCredentialConfig, StsClient};
use crate::aws::port::{AwsSecretPort, ClientExchange};

/// What the operator configured for one AWS credential.
///
/// **Every field is non-secret.** The access key id is the `AKIA…` identifier
/// AWS itself prints in CloudTrail; the role ARN, region and session name are
/// things an operator types. The secret access key is the only secret involved
/// and it is not here — it stays in the vault under `credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsDeployment {
    /// The vault credential holding the long-lived secret access key, as the
    /// vault's own `CredentialId` — **not a human label**.
    ///
    /// The first version of this field was a `String` holding a label like
    /// `aws-prod`, and the request arrived carrying the vault id the CLI
    /// documents ("copy it from `asv credentials`") and validated with
    /// `CredentialId::from_wire`. So every call was refused with "no AWS
    /// deployment is configured for 5f1c2a80-…", while the deployment sat
    /// there under a name no caller could ever send. Keying it by `CredentialId`
    /// makes the two agree, and matches what the GitHub verb already resolves.
    pub credential: CredentialId,
    /// The pinned STS audience. Never from a request — see the module docs.
    pub audience: Authority,
    pub region: String,
    pub role_arn: String,
    pub role_session_name: String,
    pub duration_seconds: u32,
}

impl AwsDeployment {
    /// The non-secret configuration the signer needs.
    ///
    /// `access_key_id` is deliberately absent: it is part of the *operator's*
    /// AWS identity, not of the role being assumed, and the `AssumeRole` call is
    /// signed with it. It travels as configuration rather than in the vault
    /// because AWS prints it in CloudTrail, so a secret would buy nothing.
    pub fn credential_config(&self, access_key_id: String) -> AwsCredentialConfig {
        AwsCredentialConfig {
            access_key_id,
            region: self.region.clone(),
            role_arn: self.role_arn.clone(),
            role_session_name: self.role_session_name.clone(),
            duration_seconds: self.duration_seconds,
            external_id: None,
        }
    }
}

/// A deployment, its client, and the session cache in front of it.
pub struct AwsBinding {
    pub deployment: AwsDeployment,
    client: Arc<StsClient>,
    port: Arc<AwsSecretPort>,
}

impl std::fmt::Debug for AwsBinding {
    /// The deployment and nothing else. The port holds sessions, and a derived
    /// `Debug` on a type that reaches them is a leak with a `{:?}` away — which
    /// is the same reason `AwsSession` and `StsClient` each write their own.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsBinding")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl AwsBinding {
    /// Wires a deployment to a client and a cache over the long-lived key.
    ///
    /// `long_lived` is the vault port for the *operator's* key. It is borrowed
    /// once per mint, inside the cache, and never reaches anything downstream of
    /// a minted session.
    pub fn new(deployment: AwsDeployment, client: Arc<StsClient>, long_lived: Arc<dyn SecretPort>) -> Self {
        let port = AwsSecretPort::new(Arc::new(ClientExchange::new(client.clone(), long_lived)));
        Self {
            deployment,
            client,
            port: Arc::new(port),
        }
    }

    /// The client this deployment signs with.
    pub fn client(&self) -> &StsClient {
        &self.client
    }

    /// The session cache.
    pub fn port(&self) -> &AwsSecretPort {
        &self.port
    }

    /// Whether this binding is the one a request's credential names.
    ///
    /// `CredentialId` is compared as itself rather than as text: a wire id that
    /// parses is one record, and two spellings of it are the same record, so
    /// there is no case-folding decision to get wrong here.
    pub fn serves(&self, credential: &CredentialId) -> bool {
        &self.deployment.credential == credential
    }
}
