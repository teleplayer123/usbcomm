#[cfg(target_os = "windows")]
use windows::core::*;
#[cfg(target_os = "windows")]
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::*;

#[cfg(target_os = "windows")]
pub struct SetupUsbDevice {
    pub vid: u16,
    pub pid: u16,
    pub instance_id: String,
}

#[cfg(target_os = "windows")]
pub fn list_all_usb_devices() -> Vec<SetupUsbDevice> {
    unsafe {
        let mut devices = Vec::new();

        let device_info_set = match SetupDiGetClassDevsW(
            None,
            w!("USB"),
            None,
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        ) {
            Ok(handle) => handle,
            Err(_) => return devices,
        };

        let mut index = 0;

        loop {
            let mut device_info = SP_DEVINFO_DATA::default();
            device_info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

            match SetupDiEnumDeviceInfo(device_info_set, index, &mut device_info) {
                Ok(_) => (),
                Err(e) if e.code() == ERROR_NO_MORE_ITEMS.into() => break,
                Err(_) => break,
            }

            let mut buffer = [0u16; 512];
            let mut required_size = 0;

            match SetupDiGetDeviceInstanceIdW(
                device_info_set,
                &device_info,
                Some(&mut buffer),
                Some(&mut required_size),
            ) {
                Ok(_) => {
                    let instance_id =
                        String::from_utf16_lossy(&buffer[..required_size as usize - 1]);

                    if instance_id.starts_with("USB\\VID_") {
                        if let Some((vid, pid)) = parse_vid_pid(&instance_id) {
                            devices.push(SetupUsbDevice {
                                vid,
                                pid,
                                instance_id,
                            });
                        }
                    }
                },
                Err(_) => {
                    index += 1;
                    continue;
                }
            }
            index += 1;
        }

        let _ = SetupDiDestroyDeviceInfoList(device_info_set);

        devices
    }
}

#[cfg(target_os = "windows")]
fn parse_vid_pid(id: &str) -> Option<(u16, u16)> {
    let vid_start = id.find("VID_")? + 4;
    let pid_start = id.find("PID_")? + 4;

    let vid = u16::from_str_radix(&id[vid_start..vid_start + 4], 16).ok()?;
    let pid = u16::from_str_radix(&id[pid_start..pid_start + 4], 16).ok()?;

    Some((vid, pid))
}
