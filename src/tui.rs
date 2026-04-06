use ratatui::{prelude::*, widgets::*};
use std::io::{self, Read, Write};
use usb::{Device, DeviceDescriptor};

struct App {
    devices: Vec<Device>,
    selected_device: Option<usize>,
    current_screen: Screen,
}

enum Screen {
    DeviceList,
    DeviceInteraction,
}

impl App {
    fn new() -> Self {
        let devices = Device::enumerate().unwrap();
        App {
            devices,
            selected_device: None,
            current_screen: Screen::DeviceList,
        }
    }
}

fn main() {
    let app = App::new();
    let mut terminal = Terminal::new(Cursor::new()).unwrap();
    loop {
        terminal.draw(|f| {
            match app.current_screen {
                Screen::DeviceList => {
                    let device_list = List::new(
                        app.devices
                            .iter()
                            .map(|d| {
                                let desc = d.descriptor().unwrap();
                                format!("{} - {} (0x{:04x})", desc.product_name(), desc.vendor_name(), desc.vendor_id())
                            })
                            .collect(),
                    );
                    f.render_widget(device_list, f.size());
                }
                Screen::DeviceInteraction => {
                    // TODO: Implement device interaction screen
                }
            }
        }).unwrap();
        // Handle events here
    }
}