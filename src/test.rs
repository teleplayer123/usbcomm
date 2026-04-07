 main.rs
  use ratatui::prelude::*;
  use ratatui::widgets::{Block, Borders, Paragraph};
  use std::error::Error;
  use std::sync::{Arc, Mutex};
  use tokio::sync::mpsc;

  mod tui;
  mod lib;

  #[tokio::main]
  async fn main() -> Result<(), Box<dyn Error>> {
      // Initialize terminal
      let mut terminal = ratatui::init();

      // Create shared state
      let state = Arc::new(Mutex::new(lib::UsbState::new()));
      let (tx, mut rx) = mpsc::channel(10);

      // Spawn UI task
      tokio::spawn(tui::run_ui(terminal, state.clone(), tx));

      // Handle events
      while let Some(event) = rx.recv().await {
          match event {
              tui::Event::SelectDevice(index) => {
                  if let Err(e) = lib::select_device(state.clone(), index) {
                      eprintln!("Error selecting device: {}", e);
                  }
              },
              tui::Event::Read => {
                  if let Err(e) = lib::read_data(state.clone()) {
                      eprintln!("Error reading data: {}", e);
                  }
              },
              tui::Event::Write(data) => {
                  if let Err(e) = lib::write_data(state.clone(), data) {
                      eprintln!("Error writing data: {}", e);
                  }
              },
              _ => {}
          }
      }

      Ok(())
  }

  tui.rs
  use ratatui::prelude::*;
  use ratatui::widgets::{Block, Borders, Paragraph};
  use std::sync::{Arc, Mutex};
  use tokio::sync::mpsc;

  pub enum Event {
      SelectDevice(usize),
      Read,
      Write(String),
  }

  pub async fn run_ui(
      mut terminal: Terminal<impl Backend>,
      state: Arc<Mutex<lib::UsbState>>,
      tx: mpsc::Sender<Event>,
  ) {
      let mut state = state.lock().unwrap();

      loop {
          terminal.draw(|frame| {
              let mut area = frame.size();

              // Draw header
              frame.render_widget(
                  Block::default()
                      .title("USB Device Manager")
                      .borders(Borders::ALL),
                  area
              );

              // Draw device list
              let devices = state.devices.clone();
              let device_list = Paragraph::new(devices.iter().map(|d| d.name.clone()).collect::<Vec<_>>())
                  .block(Block::default().borders(Borders::ALL));

              area.height = 10;
              frame.render_widget(device_list, area);

              // Draw status
              let status = match &state.current_device {
                  Some(dev) => format!("Selected: {}", dev.name),
                  None => "No device selected".to_string(),
              };

              frame.render_widget(
                  Paragraph::new(status),
                  Area::new(0, 10, 20, 3)
              );
          }).unwrap();

          if let Ok(event) = terminal.poll_event() {
              match event {
                  Event::Key(key) => {
                      match key {
                          Key::Char('q') => break,
                          Key::Char('n') => {
                              tx.send(Event::SelectDevice(state.selected_index)).await.unwrap();
                          },
                          Key::Char('r') => {
                              tx.send(Event::Read).await.unwrap();
                          },
                          Key::Char('w') => {
                              let mut input = String::new();
                              std::io::stdin().read_line(&mut input).unwrap();
                              tx.send(Event::Write(input.trim().to_string())).await.unwrap();
                          },
                          _ => {}
                      }
                  },
                  _ => {}
              }
          }
      }
  }

  lib.rs
  use rusb::DeviceHandle;
  use std::collections::VecDeque;
  use std::sync::{Arc, Mutex};

  pub struct UsbState {
      devices: Vec<UsbDevice>,
      selected_index: usize,
      current_device: Option<DeviceHandle>,
      read_buffer: VecDeque<u8>,
  }

  impl UsbState {
      pub fn new() -> Self {
          UsbState {
              devices: Vec::new(),
              selected_index: 0,
              current_device: None,
              read_buffer: VecDeque::new(),
          }
      }

      pub fn list_devices(&mut self) -> Result<(), rusb::Error> {
          self.devices = rusb::devices()
              .map(|dev| UsbDevice {
                  vid: dev.bus_id().unwrap_or(0),
                  pid: dev.product_id().unwrap_or(0),
                  name: format!("USB Device {}", self.devices.len() + 1),
              })
              .collect();

          Ok(())
      }

      pub fn select_device(&mut self, index: usize) -> Result<(), rusb::Error> {
          if index >= self.devices.len() {
              return Err(rusb::Error::InvalidArgument);
          }

          self.selected_index = index;
          self.current_device = Some(self.devices[index].open()?);

          Ok(())
      }

      pub fn read_data(&mut self) -> Result<Vec<u8>, rusb::Error> {
          let mut buffer = [0u8; 64];
          let bytes_read = self.current_device.as_ref().unwrap().read(&mut buffer)?;

          self.read_buffer.extend_from_slice(&buffer[..bytes_read]);
          Ok(self.read_buffer.clone())
      }

      pub fn write_data(&mut self, data: &str) -> Result<(), rusb::Error> {
          let buffer: Vec<u8> = data.bytes().collect();
          self.current_device.as_ref().unwrap().write(&buffer)?;
          Ok(())
      }
  }

  struct UsbDevice {
      vid: u16,
      pid: u16,
      name: String,
  }