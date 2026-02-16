mod setupapi;

use rusb::{Device, DeviceHandle, Direction, TransferType, UsbContext};
use std::time::Duration;
use clap::{Parser, Args};

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
    pub fn new(device: &Device<rusb::Context>) -> Result<Self, rusb::Error> {
        let device_descriptor = device.device_descriptor()?;
        let handle = device.open()?;

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

fn get_string_descriptor(handle: &DeviceHandle<rusb::Context>, index: Option<u8>) -> Option<String> {
    index.map(|idx| {
        handle.read_string_descriptor_ascii(idx).unwrap_or_else(|_| String::from("Unknown"))
    })
}

pub fn list_usb_devices() -> Result<Vec<UsbDeviceDescriptor>, rusb::Error> {
    let context = rusb::Context::new()?;
    let devices = context.devices()?;

    let mut device_list = Vec::new();

    for device in devices.iter() {
        match UsbDeviceDescriptor::new(&device) {
            Ok(descriptor) => {
                device_list.push(descriptor);
            }
            Err(_) => {
                // Skip devices that can't be opened or queried
                continue;
            }
        }
    }

    Ok(device_list)
}

pub fn find_device_by_vid_pid(vendor_id: u16, product_id: u16) -> Result<Option<Device<rusb::Context>>, rusb::Error> {
    let context = rusb::Context::new()?;
    let devices = context.devices()?;

    for device in devices.iter() {
        let device_descriptor = device.device_descriptor()?;
        if device_descriptor.vendor_id() == vendor_id && device_descriptor.product_id() == product_id {
            return Ok(Some(device));
        }
    }

    Ok(None)
}

pub fn find_device_by_serial(serial_number: &str) -> Result<Option<Device<rusb::Context>>, rusb::Error> {
    let context = rusb::Context::new()?;
    let devices = context.devices()?;

    for device in devices.iter() {
        let handle = device.open()?;
        let device_descriptor = device.device_descriptor()?;
        let serial = get_string_descriptor(&handle, device_descriptor.serial_number_string_index());

        if let Some(ref s) = serial {
            if s == serial_number {
                return Ok(Some(device));
            }
        }
    }

    Ok(None)
}

#[cfg(target_os = "windows")]
fn list_setupapi_devices() {
    let devices = setupapi::list_all_usb_devices();

    for dev in devices {
        println!(
            "VID: {:04X}, PID: {:04X}, {}",
            dev.vid, dev.pid, dev.instance_id
        );
    }
}

#[derive(Parser, Debug)]
#[command(name = "usb_device_communicator")]
#[command(version = "1.0")]
#[command(about = "USB device communicator with CLI support", long_about = None)]
struct Cli {
    #[command(flatten)]
    search_options: SearchOptions,

    /// List all USB devices instead of searching
    #[arg(long = "list-all", help = "List all USB devices")]
    list_all: bool,
    #[arg(long = "communicate", help = "Communicate with the found device")]
    communicate: bool,

    /// Data to write (hex format, e.g., 0x010203)
    #[arg(long = "write", help = "Data to write in hex format (e.g., 0x010203)")]
    write_data: Option<String>,

    /// Number of bytes to read
    #[arg(long = "read", help = "Number of bytes to read")]
    read_bytes: Option<usize>,
}

fn parse_hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u16::from_str_radix(s, 16)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[derive(Args, Debug)]
struct SearchOptions {
    /// Vendor ID to search for (hex format, e.g., 0x0483)
    #[arg(short = 'v', long = "vendor", help = "Vendor ID in hex format (e.g., 0x0483)", value_parser = parse_hex_u16)]
    vendor_id: Option<u16>,

    /// Product ID to search for (hex format, e.g., 0x3748)
    #[arg(short = 'p', long = "product", help = "Product ID in hex format (e.g., 0x3748)", value_parser = parse_hex_u16)]
    product_id: Option<u16>,

    /// Serial number to search for
    #[arg(short = 's', long = "serial", help = "Serial number to search for")]
    serial: Option<String>,
}

// Define endpoint information struct
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

pub struct UsbDeviceCommunicator {
    handle: DeviceHandle<rusb::Context>,
    endpoints: Vec<EndpointInfo>,
}

impl UsbDeviceCommunicator {
    pub fn new(device: Device<rusb::Context>) -> Result<Self, rusb::Error> {
        let handle = device.open()?;

        // Enumerate endpoints
        let mut endpoints = Vec::new();
        if let Ok(config_descriptor) = device.config_descriptor(0) {
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

        Ok(UsbDeviceCommunicator {
            handle,
            endpoints,
        })
    }

    pub fn read_data(&self, length: usize) -> Result<Vec<u8>, rusb::Error> {
        // Find bulk IN endpoint
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
        // Find bulk OUT endpoint
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        let devices = list_usb_devices();
        for device in devices.clone().unwrap_or_default() {
            println!("Found device: {:?}", device);
        }
        assert!(devices.is_ok());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.list_all {
        println!("\nListing all USB devices:");
        let devices = list_usb_devices()?;
        for device in devices {
            println!("VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                     device.vendor_id, device.product_id, device.manufacturer.unwrap(), device.product.unwrap(), device.serial_number);
        }
        #[cfg(target_os = "windows")]
        list_setupapi_devices();

        return Ok(());
    }

    if cli.communicate {
        if let (Some(vendor_id), Some(product_id)) = (cli.search_options.vendor_id, cli.search_options.product_id) {
            let device = find_device_by_vid_pid(vendor_id, product_id)?.ok_or("Device not found")?;
            let comm = UsbDeviceCommunicator::new(device)?;
            println!("Communicating with device VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);

            // Print discovered endpoints
            println!("Discovered endpoints:");
            for ep in comm.get_endpoints() {
                println!("{}", ep);
            }

            // Handle write operation
            if let Some(write_hex) = cli.write_data {
                let data = parse_hex_bytes(&write_hex)?;
                match comm.write_data(&data) {
                    Ok(bytes_written) => println!("Successfully wrote {} bytes", bytes_written),
                    Err(e) => eprintln!("Write error: {}", e),
                }
            }

            // Handle read operation
            if let Some(read_bytes) = cli.read_bytes {
                match comm.read_data(read_bytes) {
                    Ok(data) => {
                        println!("Read {} bytes: {:?}", data.len(), data);
                        println!("Hex: 0x{}", data.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                    }
                    Err(e) => eprintln!("Read error: {}", e),
                }
            }
        } else {
            println!("Please provide both vendor ID and product ID to communicate with a device.");
        }
        return Ok(());
    }

    // Search for specific device
    if let (Some(vendor_id), Some(product_id)) = (cli.search_options.vendor_id, cli.search_options.product_id) {
        println!("Searching for device with VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);
        match find_device_by_vid_pid(vendor_id, product_id)? {
            Some(device) => {
                println!("Found device!");
                let descriptor = UsbDeviceDescriptor::new(&device)?;
                println!("Device found: VID: 0x{:04X}, PID: 0x{:04X}", descriptor.vendor_id, descriptor.product_id);
                println!("Manufacturer: {:?}", descriptor.manufacturer.unwrap());
                println!("Product: {:?}", descriptor.product.unwrap());
                println!("Serial: {:?}", descriptor.serial_number);
            }
            None => {
                println!("No device found with VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);
            }
        }
    } else if let Some(serial) = &cli.search_options.serial {
        println!("Searching for device with serial: {}", serial);

        match find_device_by_serial(serial)? {
            Some(device) => {
                println!("Found device!");
                let descriptor = UsbDeviceDescriptor::new(&device)?;
                println!("Device found: VID: 0x{:04X}, PID: 0x{:04X}", descriptor.vendor_id, descriptor.product_id);
                println!("Manufacturer: {:?}", descriptor.manufacturer.unwrap());
                println!("Product: {:?}", descriptor.product.unwrap());
                println!("Serial: {:?}", descriptor.serial_number);
            }
            None => {
                println!("No device found with serial: {}", serial);
            }
        }
    } else {
        // No specific search criteria provided, list all devices
        println!("\nListing all USB devices:");
        let devices = list_usb_devices()?;
        for device in devices {
            println!("VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                     device.vendor_id, device.product_id, device.manufacturer.unwrap(), device.product.unwrap(), device.serial_number);
        }
    }

    Ok(())
}