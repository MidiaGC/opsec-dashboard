use std::time::{Duration, SystemTime};

use crate::checks::{self, CheckResult};

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

pub struct App {
    pub last_refresh: SystemTime,
    pub checks: Vec<CheckResult>,
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            last_refresh: SystemTime::UNIX_EPOCH,
            checks: Vec::new(),
        };
        app.refresh();
        app
    }

    /// Test/fixture constructor: build an App with given checks without
    /// invoking the real check functions.
    pub fn with_checks(checks: Vec<CheckResult>) -> Self {
        Self {
            last_refresh: SystemTime::UNIX_EPOCH,
            checks,
        }
    }

    pub fn refresh(&mut self) {
        self.checks = vec![
            checks::vpn_status(),
            checks::dnscrypt_status(),
            checks::mac_randomization(),
            checks::nftables_status(),
            checks::failed_logins(),
            checks::secure_boot(),
            checks::apparmor(),
            checks::listening_services(),
            checks::usbguard(),
        ];
        self.last_refresh = SystemTime::now();
    }

    /// Returns true if the app state changed and needs a redraw.
    pub fn tick(&mut self) -> bool {
        if self.last_refresh.elapsed().unwrap_or(Duration::ZERO) >= REFRESH_INTERVAL {
            self.refresh();
            true
        } else {
            false
        }
    }
}
