use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use opsec_dashboard::app::{ActionState, App};
use opsec_dashboard::checks;
use opsec_dashboard::cli::{self, Mode, Parsed};
use opsec_dashboard::config;
use opsec_dashboard::exec;
use opsec_dashboard::history::History;
use opsec_dashboard::report;
use opsec_dashboard::ui::{self, UiState};

/// Idle poll interval. Short enough that resizes and keys feel immediate,
/// long enough to stay off the CPU.
const IDLE_POLL: Duration = Duration::from_millis(400);
/// Poll interval while checks are in flight, so the spinner animates.
const BUSY_POLL: Duration = Duration::from_millis(120);

fn main() -> ExitCode {
    let config = match cli::parse(std::env::args().skip(1)) {
        Parsed::Run(config) => config,
        Parsed::Help => {
            print!("{}", cli::USAGE);
            return ExitCode::SUCCESS;
        }
        Parsed::Version => {
            println!("{} {}", cli::NAME, cli::VERSION);
            return ExitCode::SUCCESS;
        }
        Parsed::List => {
            print!("{}", cli::render_list());
            return ExitCode::SUCCESS;
        }
        Parsed::WriteConfig => {
            print!("{}", config::TEMPLATE);
            return ExitCode::SUCCESS;
        }
        Parsed::Error(message) => {
            eprintln!("error: {message}\n\nTry --help.");
            return ExitCode::from(64); // EX_USAGE
        }
    };

    // The file supplies the defaults; explicit flags win over it.
    let mut settings = match config::load(config.config_path.as_ref(), config.profile.as_deref()) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(78); // EX_CONFIG
        }
    };
    if let Some(interval) = config.interval {
        settings.interval = interval;
    }
    if !config.allow_sudo {
        settings.sudo = false;
    }

    exec::set_allow_sudo(settings.sudo);
    let interval = settings.interval;
    let history_settings = settings.history.clone();
    config::install(settings);

    // Validated during parsing, so this cannot fail here.
    let mut specs = checks::select(&config.only).unwrap_or_default();
    // `--only` is an explicit request and outranks the config file; the file's
    // enable/disable lists apply only when the user did not name checks.
    if config.only.is_empty() {
        specs.retain(|c| config::current().runs(c.id));
    }

    if specs.is_empty() {
        eprintln!("error: every check is disabled — nothing to do.");
        return ExitCode::from(64);
    }

    match config.mode {
        Mode::Text | Mode::Json => run_headless(&specs, config.mode),
        Mode::Tui => {
            let history = if history_settings.enabled {
                History::open(
                    opsec_dashboard::history::default_path(),
                    history_settings.retain,
                )
            } else {
                History::ephemeral(1)
            };
            match run_tui(specs, interval, history) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run_headless(specs: &[&'static checks::Check], mode: Mode) -> ExitCode {
    let results = checks::run_all(specs);
    let text = match mode {
        Mode::Json => report::render_json(&results),
        _ => report::render_text(&results),
    };
    print!("{text}");
    let _ = io::stdout().flush();
    ExitCode::from(report::exit_code(&results) as u8)
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

fn run_tui(
    specs: Vec<&'static checks::Check>,
    interval: Duration,
    history: History,
) -> io::Result<()> {
    install_panic_hook();
    enable_raw_mode()?;
    // Mouse capture is deliberately not enabled: it would break the
    // terminal's own selection and copy, and nothing here needs the mouse.
    execute!(io::stdout(), EnterAlternateScreen)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut app = App::with_config(specs, interval, config::current().clone(), history);
    let mut ui_state = UiState::default();

    let result = event_loop(&mut terminal, &mut app, &mut ui_state);

    restore_terminal();
    let _ = terminal.show_cursor();
    result
}

fn event_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    ui_state: &mut UiState,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app, ui_state))?;

        let poll_for = if app.is_busy() { BUSY_POLL } else { IDLE_POLL };
        if event::poll(poll_for)? {
            match event::read()? {
                // Filtering on Press matters: terminals speaking the kitty
                // keyboard protocol also deliver Repeat and Release, which
                // would otherwise fire every binding two or three times.
                Event::Key(key)
                    if key.kind == KeyEventKind::Press && handle_key(app, key) == Flow::Quit =>
                {
                    return Ok(());
                }
                _ => {}
            }
        }

        app.poll();
        app.poll_action();
        app.tick();
        if app.is_busy() {
            app.advance_spinner();
        }
    }
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Quit,
}

fn handle_key(app: &mut App, key: KeyEvent) -> Flow {
    // Raw mode swallows SIGINT, so Ctrl-C has to be handled explicitly or the
    // only way out would be `q`.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return Flow::Quit;
    }

    // The action overlay is modal: while it is up, no key reaches the board.
    // Nothing here can start a command except an explicit `y` on a Confirm.
    match &app.action {
        ActionState::Confirm { .. } => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_action(),
                KeyCode::Char('d') | KeyCode::Char('D') => app.dry_run_action(),
                _ => app.cancel_action(),
            }
            return Flow::Continue;
        }
        ActionState::Running { .. } => return Flow::Continue,
        ActionState::Done { .. } => {
            app.cancel_action();
            return Flow::Continue;
        }
        ActionState::Idle => {}
    }

    if app.show_help {
        match key.code {
            KeyCode::Char('q') => return Flow::Quit,
            _ => app.show_help = false,
        }
        return Flow::Continue;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Flow::Quit,
        KeyCode::Char('r') => app.refresh(),
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('g') | KeyCode::Home => app.select_first(),
        KeyCode::Char('G') | KeyCode::End => app.select_last(),
        KeyCode::Char('a') => app.auto_refresh = !app.auto_refresh,
        KeyCode::Char('s') => app.toggle_sort(),
        KeyCode::Char('f') => app.toggle_filter(),
        KeyCode::Char('+') | KeyCode::Char('=') => app.adjust_interval(1),
        KeyCode::Char('-') => app.adjust_interval(-1),
        KeyCode::Char('x') | KeyCode::Enter => {
            app.propose_action();
        }
        KeyCode::Char('?') | KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
    Flow::Continue
}

// ---------------------------------------------------------------------------
// Terminal lifecycle
// ---------------------------------------------------------------------------

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Without this, a panic anywhere leaves the user staring at a raw-mode
/// alternate screen with no echo and no prompt.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}
