use rusb::{Device, DeviceHandle, Direction, TransferType, Context, UsbContext};
use std::time::Duration;
use clap::Args;
use clap::Parser;

pub mod tui;

#[cfg(target_os = "windows")]
pub mod setupapi;

pub type UsbDevice = Device<Context>;
pub type UsbHandle = DeviceHandle<Context>;

#[derive(Debug, Clone)]
pub struct UsbDeviceDescriptor {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub bus_number: u8,
    pub device_address: u8,
}

impl UsbDeviceDescriptor {
    pub fn new(device: &UsbDevice) -> Result<Self, rusb::Error> {
        let handle = device.open()?;
        let device_descriptor = device.device_descriptor()?;
        let manufacturer = get_string_descriptor(&handle, device_descriptor.manufacturer_string_index());
        let product = get_string_descriptor(&handle, device_descriptor.product_string_index());
        let serial_number = get_string_descriptor(&handle, device_descriptor.serial_number_string_index());

        Ok(UsbDeviceDescriptor {
            vendor_id: device_descriptor.vendor_id(),
            product_id: device_descriptor.product_id(),
            manufacturer,
            product,
            serial_number,
            bus_number: device.bus_number(),
            device_address: device.address(),
        })
    }
}

fn get_string_descriptor(handle: &UsbHandle, index: Option<u8>) -> Option<String> {
    index.and_then(|idx| {
        handle.read_string_descriptor_ascii(idx).ok()
    })
}

pub fn parse_hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u16::from_str_radix(s, 16)
}

pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[derive(Clone)]
pub struct EndpointInfo {
    pub address: u8,
    pub direction: Direction,
    pub transfer_type: TransferType,
    pub max_packet_size: u16,
}

impl std::fmt::Display for EndpointInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint Address: 0x{:02X}, Direction: {:?}, Transfer Type: {:?}, Max Packet Size: {}",
               self.address, self.direction, self.transfer_type, self.max_packet_size)
    }
}

pub fn get_endpoints(handle: &UsbHandle) -> Vec<EndpointInfo> {
    let mut endpoints = Vec::new();
    if let Ok(config_descriptor) = handle.device().config_descriptor(0) {
        for interface in config_descriptor.interfaces() {
            for interface_descriptor in interface.descriptors() {
                for endpoint in interface_descriptor.endpoint_descriptors() {
                    endpoints.push(EndpointInfo {
                        address: endpoint.address(),
                        direction: endpoint.direction(),
                        transfer_type: endpoint.transfer_type(),
                        max_packet_size: endpoint.max_packet_size(),
                    });
                }
            }
        }
    }
    endpoints
}

pub struct UsbDeviceCommunicator {
    handle: UsbHandle,
    endpoints: Vec<EndpointInfo>,
}

impl UsbDeviceCommunicator {
    pub fn new(handle: UsbHandle) -> Result<Self, rusb::Error> {
        let endpoints = get_endpoints(&handle);

        Ok(UsbDeviceCommunicator {
            handle,
            endpoints,
        })
    }

    pub fn read_data(&self, length: usize) -> Result<Vec<u8>, rusb::Error> {
        let endpoint = self.endpoints
            .iter()
            .find(|ep| ep.direction == Direction::In && ep.transfer_type == TransferType::Bulk)
            .ok_or(rusb::Error::NotFound)?;

        let mut buffer = vec![0u8; length];
        let actual_length = self.handle.read_bulk(endpoint.address, &mut buffer, Duration::from_secs(1))?;
        buffer.truncate(actual_length);
        Ok(buffer)
    }

    pub fn write_data(&self, data: &[u8]) -> Result<usize, rusb::Error> {
        let endpoint = self.endpoints
            .iter()
            .find(|ep| ep.direction == Direction::Out && ep.transfer_type == TransferType::Bulk)
            .ok_or(rusb::Error::NotFound)?;

        self.handle.write_bulk(endpoint.address, data, Duration::from_secs(1))
    }

    pub fn read_control(&self, request_type: u8, request: u8, value: u16, index: u16, length: usize) -> Result<Vec<u8>, rusb::Error> {
        let mut buffer = vec![0u8; length];
        let actual_length = self.handle.read_control(
            request_type,
            request,
            value,
            index,
            &mut buffer,
            Duration::from_secs(1)
        )?;
        buffer.truncate(actual_length);
        Ok(buffer)
    }

    pub fn write_control(&self, request_type: u8, request: u8, value: u16, index: u16, data: &[u8]) -> Result<usize, rusb::Error> {
        self.handle.write_control(
            request_type,
            request,
            value,
            index,
            data,
            Duration::from_secs(1)
        )
    }

    pub fn get_endpoints(&self) -> &[EndpointInfo] {
        &self.endpoints
    }
}

pub fn list_usb_devices() -> Result<Vec<UsbDeviceDescriptor>, rusb::Error> {
    let context = Context::new()?;
    let devices = context.devices()?;
    let mut device_list = Vec::new();

    for device in devices.iter() {
        match UsbDeviceDescriptor::new(&device) {
            Ok(descriptor) => {
                device_list.push(descriptor);
            }
            Err(_) => {
                continue;
            }
        }
    }

    Ok(device_list)
}

pub fn find_device_by_vid_pid(vendor_id: u16, product_id: u16) -> Result<Option<UsbDevice>, rusb::Error> {
    let context = Context::new()?;
    let devices = context.devices()?;

    for device in devices.iter() {
        let device_descriptor = device.device_descriptor()?;
        if device_descriptor.vendor_id() == vendor_id && device_descriptor.product_id() == product_id {
            return Ok(Some(device.clone()));
        }
    }

    Ok(None)
}

pub fn find_device_by_serial(serial_number: &str) -> Result<Option<UsbDevice>, rusb::Error> {
    let context = Context::new()?;
    let devices = context.devices()?;

    for device in devices.iter() {
        let handle = device.open()?;
        let device_descriptor = device.device_descriptor()?;
        let serial = get_string_descriptor(&handle, device_descriptor.serial_number_string_index());

        if let Some(ref s) = serial {
            if s == serial_number {
                return Ok(Some(device.clone()));
            }
        }
    }

    Ok(None)
}

#[derive(Parser, Debug)]
#[command(name = "usbcomm")]
#[command(version = "0.1.0")]
#[command(about = "USB device communicator with CLI and TUI support", long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub search_options: SearchOptions,

    #[arg(long = "list-all", help = "List all USB devices")]
    pub list_all: bool,

    #[arg(long = "tui", help = "Run in TUI mode", conflicts_with_all = &["list_all"])]
    pub tui: bool,
}

#[derive(Args, Debug)]
pub struct SearchOptions {
    #[arg(short = 'v', long = "vendor", help = "Vendor ID in hex format (e.g., 0x0483)", value_parser = parse_hex_u16)]
    pub vendor_id: Option<u16>,

    #[arg(short = 'p', long = "product", help = "Product ID in hex format (e.g., 0x3748)", value_parser = parse_hex_u16)]
    pub product_id: Option<u16>,

    #[arg(short = 's', long = "serial", help = "Serial number to search for")]
    pub serial: Option<String>,
}


#[cfg(target_os = "windows")]
pub fn list_setupapi_devices() {
    // Windows-specific device enumeration via SetupAPI
    // This is a placeholder for Windows device integration
}
