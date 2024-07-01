use std::cmp::PartialEq;

use crate::memdx::auth_mechanism::AuthMechanism;
use crate::memdx::client::Result;
use crate::memdx::dispatcher::Dispatcher;
use crate::memdx::error::CancellationErrorKind::{RequestCancelled, Timeout};
use crate::memdx::error::Error;
use crate::memdx::error::Error::Generic;
use crate::memdx::op_auth_saslbyname::{OpSASLAuthByNameEncoder, SASLAuthByNameOptions};
use crate::memdx::op_bootstrap::OpBootstrapEncoder;
use crate::memdx::ops_core::OpsCore;
use crate::memdx::request::SASLListMechsRequest;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLAuthAutoOptions {
    pub username: String,
    pub password: String,

    pub enabled_mechs: Vec<AuthMechanism>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SASLListMechsOptions {}

pub trait OpSASLAutoEncoder: OpSASLAuthByNameEncoder {
    async fn sasl_auth_auto<D>(&self, dispatcher: &mut D, opts: SASLAuthAutoOptions) -> Result<()>
    where
        D: Dispatcher;

    // async fn sasl_list_mechs<D>(
    //     &self,
    //     dispatcher: &mut D,
    //     opts: SASLListMechsOptions,
    // ) -> Result<StandardPendingOp<SASLListMechsResponse>>
    // where
    //     D: Dispatcher;
}

impl OpSASLAutoEncoder for OpsCore {
    async fn sasl_auth_auto<D>(&self, dispatcher: &mut D, opts: SASLAuthAutoOptions) -> Result<()>
    where
        D: Dispatcher,
    {
        if opts.enabled_mechs.is_empty() {
            return Err(Generic(
                "Must specify at least one allowed authentication mechanism".to_string(),
            ));
        }

        let mut op = self
            .sasl_list_mechs(dispatcher, SASLListMechsRequest {})
            .await?;
        let server_mechs = op.recv().await?.available_mechs;

        // This unwrap is safe, we know it can't be None;
        let default_mech = opts.enabled_mechs.first().unwrap();

        return match self
            .sasl_auth_by_name(
                dispatcher,
                SASLAuthByNameOptions {
                    username: opts.username.clone(),
                    password: opts.password.clone(),
                    auth_mechanism: default_mech.clone(),
                },
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                if e == Error::Cancelled(Timeout) || e == Error::Cancelled(RequestCancelled) {
                    return Err(e);
                }

                // There is no obvious way to differentiate between a mechanism being unsupported
                // and the credentials being wrong.  So for now we just assume any error should be
                // ignored if our list-mechs doesn't include the mechanism we used.
                // If the server supports the default mech, it means this error is 'real', otherwise
                // we try with one of the mechanisms that we now know are supported
                let supports_default_mech = server_mechs.contains(default_mech);
                if supports_default_mech {
                    return Err(e);
                }

                let selected_mech = opts
                    .enabled_mechs
                    .iter()
                    .find(|item| server_mechs.contains(item));

                let selected_mech = match selected_mech {
                    Some(mech) => mech,
                    None => {
                        return Err(Generic(format!(
                            "No supported auth mechanism was found (enabled: {:?}, server: {:?})",
                            opts.enabled_mechs, server_mechs
                        )));
                    }
                };

                self.sasl_auth_by_name(
                    dispatcher,
                    SASLAuthByNameOptions {
                        username: opts.username.clone(),
                        password: opts.password.clone(),
                        auth_mechanism: selected_mech.clone(),
                    },
                )
                .await
            }
        };
    }
}
