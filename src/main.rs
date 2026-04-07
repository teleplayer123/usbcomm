use clap::Parser;
use usbcomm::{list_usb_devices, UsbDeviceDescriptor, Cli};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.list_all {
        println!("\nListing all USB devices:");
        let devices = list_usb_devices()?;
        for device in devices {
            println!(
                "VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                device.vendor_id, device.product_id, device.manufacturer,
                device.product, device.serial_number
            );
        }
        return Ok(());
    }

    if cli.tui {
        usbcomm::tui::run()?;
        return Ok(());
    }

    if let (Some(vendor_id), Some(product_id)) = (cli.search_options.vendor_id, cli.search_options.product_id) {
        println!("Searching for device with VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);
        match usbcomm::find_device_by_vid_pid(vendor_id, product_id)? {
            Some(_device) => {
                println!("Found device!");
                let descriptor = UsbDeviceDescriptor::new(&_device)?;
                println!("Device found: VID: 0x{:04X}, PID: 0x{:04X}", descriptor.vendor_id, descriptor.product_id);
                println!("Manufacturer: {:?}", descriptor.manufacturer);
                println!("Product: {:?}", descriptor.product);
                println!("Serial: {:?}", descriptor.serial_number);
            }
            None => {
                println!("No device found with VID: 0x{:04X}, PID: 0x{:04X}", vendor_id, product_id);
            }
        }
    } else if let Some(serial) = &cli.search_options.serial {
        println!("Searching for device with serial: {}", serial);

        match usbcomm::find_device_by_serial(serial)? {
            Some(_device) => {
                println!("Found device!");
                let descriptor = UsbDeviceDescriptor::new(&_device)?;
                println!("Device found: VID: 0x{:04X}, PID: 0x{:04X}", descriptor.vendor_id, descriptor.product_id);
                println!("Manufacturer: {:?}", descriptor.manufacturer);
                println!("Product: {:?}", descriptor.product);
                println!("Serial: {:?}", descriptor.serial_number);
            }
            None => {
                println!("No device found with serial: {}", serial);
            }
        }
    } else {
        println!("\nListing all USB devices:");
        let devices = list_usb_devices()?;
        for device in devices {
            println!(
                "VID: 0x{:04X}, PID: 0x{:04X}, Manufacturer: {:?}, Product: {:?}, Serial: {:?}",
                device.vendor_id, device.product_id, device.manufacturer,
                device.product, device.serial_number
            );
        }
    }

    Ok(())
}
