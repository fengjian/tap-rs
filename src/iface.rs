use std::os::unix::io::{AsRawFd, RawFd, IntoRawFd};
use libc::{c_int, c_uint, c_char};
use std::ffi::{CString};
use std::io::{Read, Write, Result};
use serde::{Deserialize, Serialize};
use pnet::datalink::{self};



extern {
    fn create_macvtap(ifname: *const c_char, device: *mut c_char, mtu: c_uint) -> c_int;
    fn create_tap(ifname: *const c_char, device: *mut c_char, mtu: c_uint) -> c_int;
}


#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
pub enum Mode {
    #[serde(alias = "tun")]
    Tun,
    #[serde(alias = "tap")]
    Tap,
    #[serde(alias = "macvtap")]
    MacvTap
}


#[derive(Debug, Clone)]
pub struct Iface {
    fd: i32,
    mode: Mode,
    name: String,
    ip: String,
    mac: String
}


impl Iface {
    pub fn new(ifname: &str, mode: Mode, ip: &str, mac: &str, mtu: u32) -> Result<Self> {
        let fd = unsafe {
            let t = CString::new(ifname).unwrap();
            let iface_name = t.as_ptr();
            let mut device = vec![0i8; 256];
            match mode {
                Mode::Tap => { create_tap(iface_name, device.as_mut_ptr(), mtu) },
                Mode::MacvTap => { create_macvtap(iface_name, device.as_mut_ptr(), mtu) },
                _ => { -1 }
            }
        };

        if fd < 0 {
            use std::io::{Error, ErrorKind};
            return Err(Error::new(ErrorKind::Other, "unable to create tap"));
        }

        Ok(Self {
            fd,
            mode,
            name: ifname.to_string(),
            ip: ip.to_string(),
            mac: mac.to_string()
        })
    }

    pub fn close(&mut self) -> i32 {
        unsafe {
            libc::close(self.fd)
        }
    }

    #[inline]
    pub fn get_name(&self) -> &String {
        &self.name
    }

    #[inline]
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    #[inline]
    pub fn get_mac(&self) -> &String {
        &self.mac
    }

    #[inline]
    pub fn set_mac(&mut self, mac: &str) {
        self.mac = mac.to_string();
    }

    #[inline]
    pub fn get_ip(&self) -> &String {
        &self.ip
    }

    #[inline]
    pub fn set_ip(&mut self, ip: &str) {
        self.ip = ip.to_string();
    }


    pub fn flush_nic(&mut self, only_mac: bool)  {
        let iface_list = datalink::interfaces();

        for iface in iface_list {
            if iface.name == self.name {
                let ips = &iface.ips;
                self.mac = iface.mac.unwrap_or("00:00:00:00:00:00".parse().unwrap()).to_string();
                if !only_mac {
                    self.ip = ips.iter()
                        .find(|&&ip| ip.is_ipv4())
                        .map(|&ip| ip.ip().to_string()).unwrap_or("0.0.0.0".to_string());
                }

                break;
            }
        }
    }
}


impl AsRawFd for Iface {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}


impl IntoRawFd for Iface {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}


impl Read for &Iface {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= isize::max_value() as usize);
        match unsafe { libc::read(self.fd, buf.as_mut_ptr() as _, buf.len()) } {
            x if x < 0 => Err(std::io::Error::last_os_error()),
            x => Ok(x as usize),
        }
    }
}


impl Read for Iface {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= isize::max_value() as usize);
        match unsafe { libc::read(self.fd, buf.as_mut_ptr() as _, buf.len()) } {
            x if x < 0 => Err(std::io::Error::last_os_error()),
            x => Ok(x as usize),
        }
    }
}


impl Write for &Iface {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        assert!(buf.len() <= isize::max_value() as usize);
        match unsafe { libc::write(self.fd, buf.as_ptr() as _, buf.len()) } {
            x if x < 0 => Err(std::io::Error::last_os_error()),
            x => Ok(x as usize),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}


impl Write for Iface {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        assert!(buf.len() <= isize::max_value() as usize);
        match unsafe { libc::write(self.fd, buf.as_ptr() as _, buf.len()) } {
            x if x < 0 => Err(std::io::Error::last_os_error()),
            x => Ok(x as usize),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}


impl Drop for Iface {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

