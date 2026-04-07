use crate::{list_usb_devices, UsbDeviceDescriptor, UsbDeviceCommunicator};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::io;

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    DeviceList,
    DeviceDetails,
    ReadWrite,
}

pub struct TuiApp {
    devices: Vec<UsbDeviceDescriptor>,
    selected_index: usize,
    current_screen: Screen,
    input_buffer: String,
    read_result: Option<String>,
    write_result: Option<String>,
    error: Option<String>,
    running: bool,
}

impl TuiApp {
    pub fn new() -> io::Result<Self> {
        let devices = list_usb_devices()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("USB error: {}", e)))?;

        Ok(TuiApp {
            devices,
            selected_index: 0,
            current_screen: Screen::DeviceList,
            input_buffer: String::new(),
            read_result: None,
            write_result: None,
            error: None,
            running: true,
        })
    }

    fn handle_input(&mut self, event: Event) {
        match event {
            Event::Key(key_event) => {
                match (self.current_screen.clone(), key_event.code) {
                    (Screen::DeviceList, KeyCode::Char('q')) if key_event.modifiers == KeyModifiers::CONTROL => {
                        self.running = false;
                    }
                    (Screen::DeviceList, KeyCode::Up) => {
                        if self.selected_index > 0 {
                            self.selected_index -= 1;
                        }
                    }
                    (Screen::DeviceList, KeyCode::Down) => {
                        if self.selected_index < self.devices.len().saturating_sub(1) {
                            self.selected_index += 1;
                        }
                    }
                    (Screen::DeviceList, KeyCode::Enter) => {
                        self.current_screen = Screen::DeviceDetails;
                    }
                    (Screen::DeviceDetails, KeyCode::Esc) => {
                        self.current_screen = Screen::DeviceList;
                    }
                    (Screen::DeviceDetails, KeyCode::Char('q')) if key_event.modifiers == KeyModifiers::CONTROL => {
                        self.running = false;
                    }
                    (Screen::DeviceDetails, KeyCode::Char('r')) => {
                        self.current_screen = Screen::ReadWrite;
                        self.input_buffer.clear();
                        self.read_result = None;
                        self.write_result = None;
                        self.perform_read();
                    }
                    (Screen::DeviceDetails, KeyCode::Char('w')) => {
                        self.current_screen = Screen::ReadWrite;
                        self.input_buffer.clear();
                        self.read_result = None;
                        self.write_result = None;
                    }
                    (Screen::ReadWrite, KeyCode::Esc) => {
                        self.current_screen = Screen::DeviceDetails;
                        self.input_buffer.clear();
                    }
                    (Screen::ReadWrite, KeyCode::Enter) => {
                        if !self.input_buffer.is_empty() {
                            self.perform_write();
                        }
                    }
                    (Screen::ReadWrite, KeyCode::Backspace) => {
                        self.input_buffer.pop();
                    }
                    (Screen::ReadWrite, KeyCode::Char(c)) => {
                        self.input_buffer.push(c);
                    }
                    (_, KeyCode::Char('q')) if key_event.modifiers == KeyModifiers::CONTROL => {
                        self.running = false;
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }

    fn perform_read(&mut self) {
        if self.selected_index >= self.devices.len() {
            self.error = Some("No device selected".to_string());
            return;
        }

        let device_info = &self.devices[self.selected_index];
        match crate::find_device_by_vid_pid(device_info.vendor_id, device_info.product_id) {
            Ok(Some(device)) => {
                match device.open() {
                    Ok(handle) => {
                        match UsbDeviceCommunicator::new(handle) {
                            Ok(communicator) => {
                                match communicator.read_data(64) {
                                    Ok(data) => {
                                        let hex_string = data.iter()
                                            .map(|b| format!("{:02X}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        self.read_result = Some(format!("[{}]", hex_string));
                                    }
                                    Err(e) => {
                                        self.error = Some(format!("Read error: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.error = Some(format!("Communicator error: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        self.error = Some(format!("Open error: {}", e));
                    }
                }
            }
            Ok(None) => {
                self.error = Some("Device not found".to_string());
            }
            Err(e) => {
                self.error = Some(format!("Search error: {}", e));
            }
        }
    }

    fn perform_write(&mut self) {
        if self.selected_index >= self.devices.len() {
            self.error = Some("No device selected".to_string());
            return;
        }

        let device_info = &self.devices[self.selected_index];
        match crate::find_device_by_vid_pid(device_info.vendor_id, device_info.product_id) {
            Ok(Some(device)) => {
                match device.open() {
                    Ok(handle) => {
                        match UsbDeviceCommunicator::new(handle) {
                            Ok(communicator) => {
                                let data = self.input_buffer.as_bytes();
                                match communicator.write_data(data) {
                                    Ok(count) => {
                                        self.write_result = Some(format!("Wrote {} bytes", count));
                                        self.input_buffer.clear();
                                    }
                                    Err(e) => {
                                        self.error = Some(format!("Write error: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.error = Some(format!("Communicator error: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        self.error = Some(format!("Open error: {}", e));
                    }
                }
            }
            Ok(None) => {
                self.error = Some("Device not found".to_string());
            }
            Err(e) => {
                self.error = Some(format!("Search error: {}", e));
            }
        }
    }
}

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new()?;

    loop {
        terminal.draw(|f| draw_ui(f, &app))?;

        if !app.running {
            break;
        }

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Ok(event) = event::read() {
                app.handle_input(event);
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(4),
        ])
        .split(f.area());

    let header = Paragraph::new("USB Device Communicator")
        .style(Style::default().bold())
        .block(Block::default().borders(Borders::ALL).title("Header"));
    f.render_widget(header, chunks[0]);

    match app.current_screen {
        Screen::DeviceList => draw_device_list(f, app, chunks[1]),
        Screen::DeviceDetails => draw_device_details(f, app, chunks[1]),
        Screen::ReadWrite => draw_read_write(f, app, chunks[1]),
    }

    let footer_text = match app.current_screen {
        Screen::DeviceList => "↑/↓: Navigate | Enter: Select | Ctrl+Q: Quit",
        Screen::DeviceDetails => "R: Read | W: Write | Esc: Back | Ctrl+Q: Quit",
        Screen::ReadWrite => "Enter: Submit | Backspace: Delete | Esc: Cancel | Ctrl+Q: Quit",
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().italic())
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(footer, chunks[2]);
}

fn draw_device_list(f: &mut Frame, app: &TuiApp, area: Rect) {
    let items: Vec<ListItem> = app
        .devices
        .iter()
        .enumerate()
        .map(|(idx, device)| {
            let prefix = if idx == app.selected_index { "→ " } else { "  " };
            let name = device
                .product
                .as_deref()
                .unwrap_or("Unknown Product");
            ListItem::new(format!(
                "{}[{:04X}:{:04X}] {}",
                prefix, device.vendor_id, device.product_id, name
            ))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Available Devices"))
        .style(Style::default());

    f.render_widget(list, area);
}

fn draw_device_details(f: &mut Frame, app: &TuiApp, area: Rect) {
    if app.selected_index >= app.devices.len() {
        return;
    }

    let device = &app.devices[app.selected_index];
    let details = format!(
        "Vendor ID: 0x{:04X}\nProduct ID: 0x{:04X}\nManufacturer: {}\nProduct: {}\nSerial: {}",
        device.vendor_id,
        device.product_id,
        device.manufacturer.as_deref().unwrap_or("N/A"),
        device.product.as_deref().unwrap_or("N/A"),
        device.serial_number.as_deref().unwrap_or("N/A")
    );

    let paragraph = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title("Device Details"))
        .style(Style::default());

    f.render_widget(paragraph, area);
}

fn draw_read_write(f: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let input_text = Paragraph::new(app.input_buffer.clone())
        .block(Block::default().borders(Borders::ALL).title("Input"))
        .style(Style::default());
    f.render_widget(input_text, chunks[0]);

    let result = app
        .read_result
        .as_deref()
        .or_else(|| app.write_result.as_deref())
        .or_else(|| app.error.as_deref())
        .unwrap_or("");

    let result_paragraph = Paragraph::new(result)
        .block(Block::default().borders(Borders::ALL).title("Result"))
        .style(
            if app.error.is_some() {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            },
        );
    f.render_widget(result_paragraph, chunks[1]);
}
