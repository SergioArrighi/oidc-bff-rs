#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod profile;
mod session;

pub use profile::{EmailAddress, ProfileValidationError, UserProfile, UserSubject};
pub use session::{
    AuthenticationStatus, IdentityLogout, IdentitySession, IdentitySessionValidationError,
};
