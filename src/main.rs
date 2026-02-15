use rusb::{Device, DeviceHandle, Context, Direction, TransferType, UsbContext};
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
}

#[derive(Args, Debug)]
struct SearchOptions {
    /// Vendor ID to search for (hex format, e.g., 0x0483)
    #[arg(short = 'v', long = "vendor", help = "Vendor ID in hex format (e.g., 0x0483)")]
    vendor_id: Option<u16>,

    /// Product ID to search for (hex format, e.g., 0x3748)
    #[arg(short = 'p', long = "product", help = "Product ID in hex format (e.g., 0x3748)")]
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

pub struct UsbDeviceCommunicator {
    handle: DeviceHandle<Context>,
    vendor_id: u16,
    product_id: u16,
    endpoints: Vec<EndpointInfo>,
}

impl UsbDeviceCommunicator {
    pub fn new(device: Device<Context>) -> Result<Self, rusb::Error> {
        let device_descriptor = device.device_descriptor()?;
        let handle = device.open()?;

        // Discover endpoints dynamically
        let endpoints = Self::discover_endpoints(&device)?;

        Ok(UsbDeviceCommunicator {
            handle,
            vendor_id: device_descriptor.vendor_id(),
            product_id: device_descriptor.product_id(),
            endpoints,
        })
    }

    fn discover_endpoints(device: &Device<Context>) -> Result<Vec<EndpointInfo>, rusb::Error> {
        let mut endpoints = Vec::new();

        // Get the first configuration (usually 1)
        for config_num in 0..device.device_descriptor()?.num_configurations() {
            if let Ok(config) = device.config_descriptor(config_num) {
                for interface in config.interfaces() {
                    for descriptor in interface.descriptors() {
                        for endpoint in descriptor.endpoint_descriptors() {
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
        }

        Ok(endpoints)
    }

    pub fn find_bulk_in_endpoint(&self) -> Option<EndpointInfo> {
        self.endpoints.iter()
            .find(|ep| ep.direction == Direction::In && ep.transfer_type == TransferType::Bulk)
            .cloned()
    }

    pub fn find_bulk_out_endpoint(&self) -> Option<EndpointInfo> {
        self.endpoints.iter()
            .find(|ep| ep.direction == Direction::Out && ep.transfer_type == TransferType::Bulk)
            .cloned()
    }

    pub fn write_data(&mut self, data: &[u8]) -> Result<usize, rusb::Error> {
        if let Some(endpoint) = self.find_bulk_out_endpoint() {
            self.handle.write_bulk(endpoint.address, data, Duration::from_secs(1))
        } else {
            // Fallback to hardcoded if needed
            self.handle.write_bulk(0x01, data, Duration::from_secs(1))
        }
    }

    pub fn read_data(&mut self, buffer: &mut [u8]) -> Result<usize, rusb::Error> {
        if let Some(endpoint) = self.find_bulk_in_endpoint() {
            self.handle.read_bulk(endpoint.address, buffer, Duration::from_secs(1))
        } else {
            // Fallback to hardcoded if needed
            self.handle.read_bulk(0x81, buffer, Duration::from_secs(1))
        }
    }

    pub fn write_control(&mut self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<usize, rusb::Error> {
        self.handle.write_control(
            rusb::request_type(rusb::Direction::Out, rusb::RequestType::Vendor, rusb::Recipient::Device),
            request,
            value,
            index,
            data,
            Duration::from_secs(1)
        )
    }
    pub fn read_control(&mut self, request: u8, value: u16, index: u16, buffer: &mut [u8]) -> Result<usize, rusb::Error> {
        self.handle.read_control(
            rusb::request_type(rusb::Direction::In, rusb::RequestType::Vendor, rusb::Recipient::Device),
            request,
            value,
            index,
            buffer,
            Duration::from_secs(1)
        )
    }

    pub fn get_device_info(&self) -> (u16, u16) {
        (self.vendor_id, self.product_id)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("USB Device Communicator");
    println!("======================");

    if cli.list_all {
        // List all devices
        println!("\nListing all USB devices:");
        let devices = list_usb_devices()?;
        for device in devices {
            println!("VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                     device.vendor_id, device.product_id, device.manufacturer.unwrap(), device.product.unwrap(), device.serial_number);
        }
        return Ok(());
    }

    if cli.communicate {
        if let (Some(vendor_id), Some(product_id)) = (cli.search_options.vendor_id, cli.search_options.product_id) {
            let comm = UsbDeviceCommunicator::new(find_device_by_vid_pid(vendor_id, product_id)?.ok_or("Device not found")?)?;
            println!("Communicating with device VID: 0x{:04X}, PID: 0x{:04X}", comm.vendor_id, comm.product_id);
            let endpoints = comm.endpoints;
            println!("Discovered endpoints:");
            for ep in &endpoints {
                println!("Endpoint Address: 0x{:02X}, Direction: {:?}, Transfer Type: {:?}, Max Packet Size: {}",
                         ep.address, ep.direction, ep.transfer_type, ep.max_packet_size);
            }
            // TODO: Add actual communication logic here (e.g., read/write data)
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