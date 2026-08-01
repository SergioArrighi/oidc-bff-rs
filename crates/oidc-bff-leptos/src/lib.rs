#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod client;
mod gate;

pub use client::{IdentityClient, IdentityClientConfigurationError, IdentityClientError};
pub use gate::{IdentityContext, IdentityGate, IdentityGateState, IdentityProfileMenu};
