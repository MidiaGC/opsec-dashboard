//! OPSEC health dashboard — a terminal view of a Linux host's security posture.
//!
//! Layering:
//!
//! * [`exec`] — subprocess execution with timeouts, the only place that shells out.
//! * [`checks`] — the catalogue. Each check pairs an orchestrator with a pure,
//!   testable interpreter.
//! * [`app`] — dashboard state and the asynchronous refresh engine.
//! * [`ui`] — rendering. [`report`] is its headless counterpart.

pub mod alerts;
pub mod app;
pub mod checks;
pub mod cli;
pub mod config;
pub mod exec;
pub mod history;
pub mod report;
pub mod timefmt;
pub mod ui;
