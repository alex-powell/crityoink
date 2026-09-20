pub mod cli;
pub mod cpe;
pub mod csv_inv;
pub mod db;
pub mod error;
pub mod html;
pub mod nvd;

pub use error::{Error, Result};

/// Run the CLI with the given args (including argv[0]) and return a process exit code.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    cli::run(args)
}
