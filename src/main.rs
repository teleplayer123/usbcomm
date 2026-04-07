use clap::Parser;
use lib::{list_usb_devices, parse_hex_u16, parse_hex_bytes, UsbDeviceCommunicator};
use std::time::Duration;
use rusb::{Device, DeviceHandle, Direction, TransferType, UsbContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.list_all {
        println!("\nListing all USB devices:");
        let devices = lib::list_usb_devices()?;
        for device in devices {
            println!(
                "VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                device.vendor_id, device.product_id, device.manufacturer.unwrap(),
                device.product.unwrap(), device.serial_number
            );
        }
        #[cfg(target_os = "windows")]
        lib::list_setupapi_devices();

        return Ok(());
    }

    if cli.tui {
        tui::run()?;
        return Ok(());
    }

    // Search for specific device
    if let (Some(vendor_id), Some(product_id)) = (cli.search_options.vendor_id, cli.search_options.product_id) {
        println!("Searching for device with VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);
        match lib::find_device_by_vid_pid(vendor_id, product_id)? {
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

        match lib::find_device_by_serial(serial)? {
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
        let devices = lib::list_usb_devices()?;
        for device in devices {
            println!(
                "VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                device.vendor_id, device.product_id, device.manufacturer.unwrap(),
                device.product.unwrap(), device.serial_number
            );
        }
    }

    Ok(())
}

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
    pub fn new(device: &Device<UsbContext>) -> Result<Self, rusb::Error> {
        let handle = device.open()?;
        let device_descriptor = handle.device_descriptor()?;
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

fn get_string_descriptor(handle: &DeviceHandle<UsbContext>, index: Option<u8>) -> Option<String> {
    index.map(|idx| {
        handle.read_string_descriptor_ascii(idx).unwrap_or_else(|_| String::from("Unknown"))
    })
}
