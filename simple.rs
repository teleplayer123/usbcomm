use rusb::{Device, DeviceHandle, UsbContext};

fn simple_usb_communication() -> Result<(), rusb::Error> {
    let context = rusb::Context::new()?;
    let devices = context.devices()?;

    for device in devices.iter() {
        let device_descriptor = device.device_descriptor()?;
        println!("Vendor: 0x{:04X}, Product: 0x{:04X}",
                 device_descriptor.vendor_id(), device_descriptor.product_id());

        // Try to open and communicate with the device
        if let Ok(handle) = device.open() {
            // Read device information
            println!("Successfully opened device");

            // Example: Try to read configuration
            match handle.read_configuration(1000) {
                Ok(config) => {
                    println!("Configuration: {:?}", config);
                }
                Err(e) => {
                    println!("Failed to read configuration: {}", e);
                }
            }

            // Close the handle
            drop(handle);
        }
    }

    Ok(())
}