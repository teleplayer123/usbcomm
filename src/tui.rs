use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear},
    layout::{Constraint, Direction, Layout, Rect},
};
use std::io::{self, Read, Write};
use usb::{Device, DeviceDescriptor, UsbDeviceCommunicator, UsbDeviceDescriptor as UsbDeviceDescriptor};
use clap::Args;

#[derive(Debug, Clone)]
pub struct TuiDeviceDescriptor {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub bus_number: u8,
    pub device_address: u8,
    pub endpoint_count: usize,
}

impl TuiDeviceDescriptor {
    pub fn new(usb_device_descriptor: UsbDeviceDescriptor, endpoint_count: usize) -> Self {
        TuiDeviceDescriptor {
            vendor_id: usb_device_descriptor.vendor_id,
            product_id: usb_device_descriptor.product_id,
            manufacturer: usb_device_descriptor.manufacturer,
            product: usb_device_descriptor.product,
            serial_number: usb_device_descriptor.serial_number,
            bus_number: usb_device_descriptor.bus_number,
            device_address: usb_device_descriptor.device_address,
            endpoint_count,
        }
    }

    fn name(&self) -> String {
        let name = self.product.as_deref().unwrap_or("Unknown Product");
        format!("{name} (VID: 0x{:04X}, PID: 0x{:04X})", self.vendor_id, self.product_id)
    }
}

#[derive(Clone)]
pub struct TuiApp {
    devices: Vec<TuiDeviceDescriptor>,
    selected_device: Option<usize>,
    current_screen: Screen,
    read_data: Option<Vec<u8>>,
    write_data: Option<String>,
    read_result: Option<String>,
    write_result: Option<String>,
    error: Option<String>,
    instructions: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    DeviceList,
    DeviceInteraction,
    DeviceSelected,
}

pub struct SearchOptions {
    /// Vendor ID to search for (hex format, e.g., 0x0483)
    pub vendor_id: Option<u16>,
    /// Product ID to search for (hex format, e.g., 0x3748)
    pub product_id: Option<u16>,
    /// Serial number to search for
    pub serial: Option<String>,
}

impl TuiApp {
    pub fn new() -> io::Result<Self> {
        let devices = usb::list_usb_devices()?;
        let endpoints: Vec<_> = devices.iter().map(|d| d.get_endpoints().len()).collect();

        let instructions = r#"(Q)uit | (d)own | (u)p | Enter: Select Device | (r)ead | (w)rite | (c)ontrol | (l)ist endpoints"#;

        Ok(TuiApp {
            devices: devices
                .into_iter()
                .zip(endpoints)
                .map(|(d, count)| TuiDeviceDescriptor::new(d, count))
                .collect(),
            selected_device: None,
            current_screen: Screen::DeviceList,
            read_data: None,
            write_data: None,
            read_result: None,
            write_result: None,
            error: None,
            instructions: instructions.to_string(),
        })
    }

    pub fn handle_input(&mut self, key: ratatui::crossterm::event::Event) -> io::Result<()> {
        match key {
            ratatui::crossterm::event::Event::Key(key_event) => match key_event.code {
                ratatui::crossterm::event::KeyCode::Char('q') => {
                    if key_event.modifiers.contains(ratatui::crossterm::event::KeyModifiers::CONTROL) {
                        return Ok(());
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('d') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            let new_idx = if idx == 0 {
                                self.devices.len().saturating_sub(1)
                            } else {
                                idx.saturating_sub(1)
                            };
                            self.selected_device = Some(new_idx);
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('u') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            let new_idx = if idx == Some(self.devices.len() - 1) {
                                0
                            } else {
                                idx.unwrap() + 1
                            };
                            self.selected_device = Some(new_idx);
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Enter => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.current_screen = Screen::DeviceSelected;
                            self.read_result = None;
                            self.write_result = None;
                            self.error = None;
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('r') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.read_data = Some(vec![0u8; 64]);
                            self.current_screen = Screen::DeviceInteraction;
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('w') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.write_data = Some(String::new());
                            self.current_screen = Screen::DeviceInteraction;
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('c') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.current_screen = Screen::DeviceInteraction;
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('l') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.current_screen = Screen::DeviceList;
                            self.selected_device = Some(idx);
                            self.error = None;
                        }
                    }
                }
                ratatui::crossterm::event::KeyCode::Char('b') => {
                    if key_event.modifiers.is_empty() {
                        if let Some(idx) = self.selected_device {
                            self.selected_device = None;
                            self.current_screen = Screen::DeviceList;
                        }
                    }
                }
                _ => {}
            },
            ratatui::crossterm::event::Event::Resize(_, _) => {}
            _ => {}
        }

        if let Some(ref mut text) = self.write_data {
            if let ratatui::crossterm::event::Event::Key(key_event) = &key {
                if key_event.modifiers.is_empty() {
                    if let ratatui::crossterm::event::KeyCode::Char(c) = key_event.code {
                        if c.is_ascii_printable() {
                            text.push(*c as char);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn get_instructions(&self) -> String {
        match self.current_screen {
            Screen::DeviceList => {
                format!(
                    "(Q)uit | Enter: Select Device | (l)ist all | (d)eselect all | Error: {}\n{}",
                    self.error.as_deref().unwrap_or(""),
                    self.instructions
                )
            }
            Screen::DeviceInteraction => {
                match self.selected_device {
                    Some(idx) => {
                        if let Some(ref mut text) = self.write_data {
                            format!(
                                "(Q)uit | (r)eject text | (ESC) Submit | Enter: Submit | Backspace: Delete | Current: \"{}\"{}",
                                text, self.instructions
                            )
                        } else {
                            format!(
                                "(Q)uit | (r)eject | (ESC) Clear | Enter: Submit | Backspace: Delete | Current: \"{}\"{}",
                                "", self.instructions
                            )
                        }
                    }
                    None => format!("(Q)uit | (d)own | (u)p | Enter: Select Device | {}", self.instructions),
                }
            }
            Screen::DeviceSelected => {
                match self.selected_device {
                    Some(idx) => format!(
                        "Selected: {}\n\n(Q)uit | (l)ist | (r)ead | (w)rite | (c)ontrol | (b)ack | (e)ndpoints\n{}",
                        self.devices[idx].name(),
                        self.instructions
                    ),
                    None => format!("(Q)uit | (d)own | (u)p | Enter: Select Device | {}", self.instructions),
                }
            }
        }
    }

    pub fn read_data(&self) -> io::Result<Option<Vec<u8>>> {
        if let Some(idx) = self.selected_device {
            if let Some(device) = self.devices[idx].as_device() {
                let comm = UsbDeviceCommunicator::new(device)?;
                let data = comm.read_data(64)?;
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    pub fn write_data(&self, data: &[u8]) -> io::Result<usize> {
        if let Some(idx) = self.selected_device {
            if let Some(device) = self.devices[idx].as_device() {
                let comm = UsbDeviceCommunicator::new(device)?;
                let bytes_written = comm.write_data(data)?;
                return Ok(bytes_written);
            }
        }
        Ok(0)
    }

    fn as_device(&self, idx: usize) -> Option<Device<rusb::Context>> {
        if let Some(device_descriptor) = &self.devices[idx].device_descriptor {
            let handle = &self.devices[idx].handle;
            Some(Device {
                context: rusb::Context::new().unwrap(),
                descriptor: device_descriptor.clone(),
                handle,
            })
        } else {
            None
        }
    }
}

pub fn run() -> io::Result<()> {
    let mut app = TuiApp::new()?;
    let mut terminal = Terminal::new(Cursor::new())?;

    loop {
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(2),
                ])
                .split(frame.area());

            // Header
            let header = Paragraph::new("USB Device Communicator TUI")
                .style(Style::default().add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL));
            frame.render_widget(header, chunks[0]);

            // Main content
            match app.current_screen {
                Screen::DeviceList => {
                    // Device list
                    let device_block = Block::default()
                        .borders(Borders::ALL)
                        .title("Available Devices");

                    let devices_widget: Widget<'_> = if app.devices.is_empty() {
                    List::new(Vec::new())
                } else {
                    List::new(
                        app.devices
                            .iter()
                            .enumerate()
                            .map(|(idx, device)| {
                                let name = device.name();
                                let selected = if app.selected_device == Some(idx) { "* " } else { "  " };
                                format!("{}{}", selected, name)
                            })
                            .collect(),
                    )
                };
                    frame.render_widget(device_block, chunks[1]);
                    frame.render_widget(devices_widget, chunks[1]);

                    // Instructions
                    let instructions = app.get_instructions();
                    let instructions = Paragraph::new(instructions)
                        .block(Block::default().borders(Borders::ALL));
                    frame.render_widget(instructions, chunks[2]);
                }
                Screen::DeviceInteraction => {
                    let (input_text, result_text) = match app.current_screen {
                        Screen::DeviceInteraction => {
                            let input_text = if let Some(ref text) = app.write_data {
                                text.clone()
                            } else if let Some(ref data) = app.read_data {
                                format!("{:?}", data)
                            } else {
                                String::new()
                            };
                            let result_text = app
                                .read_result
                                .as_deref()
                                .or_else(|| app.write_result.as_deref())
                                .unwrap_or("");
                            (input_text, result_text)
                        }
                        _ => (String::new(), String::new()),
                    };

                    let input_block = Block::default()
                        .borders(Borders::ALL)
                        .title("Data Input");
                    let input_widget = Paragraph::new(input_text).block(input_block);
                    frame.render_widget(input_widget, chunks[1]);

                    let result_block = Block::default()
                        .borders(Borders::ALL)
                        .title("Result");
                    let result_widget = Paragraph::new(result_text)
                        .style(if result_text.is_empty() {
                            Style::default()
                        } else {
                            Style::default().add_modifier(Modifier::BOLD)
                        });
                    frame.render_widget(result_widget, chunks[1]);

                    // Instructions
                    let instructions = app.get_instructions();
                    let instructions = Paragraph::new(instructions)
                        .block(Block::default().borders(Borders::ALL));
                    frame.render_widget(instructions, chunks[2]);
                }
                Screen::DeviceSelected => {
                    // Show selected device info
                    let device_info = app.devices
                        .iter()
                        .filter(|_| app.selected_device == Some(0))
                        .next()
                        .map(|d| {
                            format!(
                                "Vendor ID: 0x{:04X}\nProduct ID: 0x{:04X}\nManufacturer: {:?}\nProduct: {:?}\nSerial: {:?}\nEndpoints: {}",
                                d.vendor_id, d.product_id, d.manufacturer, d.product, d.serial_number, d.endpoint_count
                            )
                        })
                        .unwrap_or_else(|| String::new());

                    let device_block = Block::default()
                        .borders(Borders::ALL)
                        .title("Selected Device Information");
                    let device_widget = Paragraph::new(device_info)
                        .style(Style::default().add_modifier(Modifier::BOLD));
                    frame.render_widget(device_block, chunks[1]);
                    frame.render_widget(device_widget, chunks[1]);

                    // Instructions
                    let instructions = app.get_instructions();
                    let instructions = Paragraph::new(instructions)
                        .block(Block::default().borders(Borders::ALL));
                    frame.render_widget(instructions, chunks[2]);
                }
            }
        })?;

        // Handle events
        if let Ok(Some(event)) = ratatui::crossterm::event::poll(std::time::Duration::from_millis(100)) {
            if let Ok(event) = ratatui::crossterm::event::read() {
                if let Err(_) = app.handle_input(event) {
                    continue;
                }
            }
        }
    }
}

pub mod search_options {
    use clap::Args;

    #[derive(Args, Debug, Clone)]
    pub struct TuiSearchOptions {
        /// Vendor ID to search for (hex format, e.g., 0x0483)
        #[arg(short = 'v', long = "vendor", help = "Vendor ID in hex format (e.g., 0x0483)", value_parser = super::parse_hex_u16)]
        pub vendor_id: Option<u16>,

        /// Product ID to search for (hex format, e.g., 0x3748)
        #[arg(short = 'p', long = "product", help = "Product ID in hex format (e.g., 0x3748)", value_parser = super::parse_hex_u16)]
        pub product_id: Option<u16>,

        /// Serial number to search for
        #[arg(short = 's', long = "serial", help = "Serial number to search for")]
        pub serial: Option<String>,
    }
}
