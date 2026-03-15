use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    Command,
};
use std::{
    io,
    time::{Duration, Instant},
};
use crate::{UsbDeviceDescriptor, EndpointInfo};

#[derive(Debug, Clone, PartialEq)]
pub enum AppMode {
    ListDevices,
    Search,
    Communicate,
}

#[derive(Debug)]
pub struct App {
    pub mode: AppMode,
    pub devices: Vec<UsbDeviceDescriptor>,
    pub selected_device: Option<UsbDeviceDescriptor>,
    pub search_vid: String,
    pub search_pid: String,
    pub search_serial: String,
    pub read_data: Vec<u8>,
    pub write_data: String,
    pub read_count: String,
    pub messages: Vec<Message>,
    pub status: String,
    pub scroll_offset: usize,
}

#[derive(Debug, Clone)]
pub enum Message {
    Info(String),
    Error(String),
    Warning(String),
}

impl App {
    pub fn new() -> Self {
        Self {
            mode: AppMode::ListDevices,
            devices: Vec::new(),
            selected_device: None,
            search_vid: String::new(),
            search_pid: String::new(),
            search_serial: String::new(),
            read_data: Vec::new(),
            write_data: String::new(),
            read_count: String::from("64"),
            messages: vec![Message::Info("Welcome to USB Device Communicator".to_string())],
            status: "Ready".to_string(),
            scroll_offset: 0,
        }
    }

    pub fn add_message(&mut self, msg: Message) {
        self.messages.insert(0, msg);
        if self.messages.len() > 20 {
            self.messages.truncate(20);
        }
    }

    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }
}

pub fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        terminal.draw(|frame| ui(frame, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') if matches!(app.mode, AppMode::ListDevices) => break,
                    KeyCode::Char('1') => app.mode = AppMode::ListDevices,
                    KeyCode::Char('2') => app.mode = AppMode::Search,
                    KeyCode::Char('3') => app.mode = AppMode::Communicate,
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.scroll_offset > 0 {
                            app.scroll_offset -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.scroll_offset < app.devices.len().saturating_sub(1) {
                            app.scroll_offset += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(device) = app.devices.get(app.scroll_offset) {
                            app.selected_device = Some(device.clone());
                            app.add_message(Message::Info("Device selected".to_string()));
                        }
                    }
                    KeyCode::Esc => {
                        app.selected_device = None;
                        app.scroll_offset = 0;
                    }
                    _ if app.mode == AppMode::Search => {
                        handle_search_input(key, &mut app);
                    }
                    _ if app.mode == AppMode::Communicate => {
                        handle_communicate_input(key, &mut app);
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(5),
        ])
        .split(frame.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled("USB Device Communicator", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" - "),
        Span::styled(
            match app.mode {
                AppMode::ListDevices => "List Devices",
                AppMode::Search => "Search Device",
                AppMode::Communicate => "Communicate",
            },
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Header"));

    frame.render_widget(header, chunks[0]);

    // Main content
    match app.mode {
        AppMode::ListDevices => list_devices_view(frame, chunks[1], app),
        AppMode::Search => search_view(frame, chunks[1], app),
        AppMode::Communicate => communicate_view(frame, chunks[1], app),
    }

    // Messages and status
    let messages_text: Vec<Line> = app
        .messages
        .iter()
        .map(|msg| match msg {
            Message::Info(s) => Line::from(Span::styled(s, Style::default().fg(Color::Green))),
            Message::Error(s) => Line::from(Span::styled(s, Style::default().fg(Color::Red))),
            Message::Warning(s) => Line::from(Span::styled(s, Style::default().fg(Color::Yellow))),
        })
        .collect();

    let messages = Paragraph::new(messages_text)
        .block(Block::default().borders(Borders::ALL).title("Messages"));
    frame.render_widget(messages, chunks[2]);

    let status = Paragraph::new(Line::from(vec![
        Span::raw("Press "),
        Span::styled("1", Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled("2", Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled("3", Style::default().fg(Color::Yellow)),
        Span::raw(" - Mode | "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" - Quit"),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);
}

fn list_devices_view(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    if app.devices.is_empty() {
        let msg = Paragraph::new("No devices found. Press F5 to refresh.")
            .style(Style::default().fg(Color::Yellow))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = app
        .devices
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let is_selected = i == app.scroll_offset;
            let text = format!(
                "VID: 0x{:04X} PID: 0x{:04X} {} {}",
                device.vendor_id,
                device.product_id,
                device.manufacturer.as_deref().unwrap_or("Unknown"),
                device.product.as_deref().unwrap_or("Unknown"),
            );

            ListItem::new(text).style(if is_selected {
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect();

    let device_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("USB Devices (j/k to navigate, Enter to select)"));

    frame.render_widget(device_list, area);
}

fn search_view(frame: &mut Frame, area: ratatui::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let vid_input = Paragraph::new(format!("VID (0x{}): ", app.search_vid))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(vid_input, chunks[0]);

    let pid_input = Paragraph::new(format!("PID (0x{}): ", app.search_pid))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(pid_input, chunks[1]);

    let serial_input = Paragraph::new(format!("Serial: {}", app.search_serial))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(serial_input, chunks[2]);

    let help_text = Paragraph::new("Enter values and press Enter to search | ESC to go back")
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help_text, chunks[3]);
}

fn communicate_view(frame: &mut Frame, area: ratatui::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let write_input = Paragraph::new(format!("Write Data (0x{}): ", app.write_data))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(write_input, chunks[0]);

    let read_count_input = Paragraph::new(format!("Read Count: {}", app.read_count))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(read_count_input, chunks[1]);

    let read_output = Paragraph::new(format!(
        "Last Read: {}",
        app.read_data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    ))
    .block(Block::default().borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(read_output, chunks[2]);

    let help_text = Paragraph::new("Enter data and press Enter to communicate | ESC to go back")
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help_text, chunks[3]);
}

fn handle_search_input(key: event::KeyEvent, app: &mut App) {
    match key.code {
        KeyCode::Enter => {
            if !app.search_vid.is_empty() || !app.search_pid.is_empty() {
                app.status = "Searching...".to_string();
            }
        }
        KeyCode::Esc => {
            app.mode = AppMode::ListDevices;
        }
        KeyCode::Char(c) => {
            if c == 'v' {
                app.search_vid.clear();
            } else if c == 'p' {
                app.search_pid.clear();
            } else if c == 's' {
                app.search_serial.clear();
            }
        }
        _ => {}
    }
}

fn handle_communicate_input(key: event::KeyEvent, app: &mut App) {
    match key.code {
        KeyCode::Enter => {
            app.status = "Communicating...".to_string();
        }
        KeyCode::Esc => {
            app.mode = AppMode::ListDevices;
        }
        _ => {}
    }
}