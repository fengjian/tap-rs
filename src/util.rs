use std::process::Command;
use std::process::ExitStatus;
use pnet::datalink::{self};
#[allow(unused_imports)]
use std::collections::HashMap;
#[allow(unused_imports)]
use async_std::sync::{Arc, RwLock};

#[macro_export]
macro_rules! safe_map {
($($key:expr => $value:expr), *) => {{
    let t: Arc<RwLock<HashMap<_,_>>> = Arc::new(RwLock::new(HashMap::new()));
    $(t.write().await.insert($key, $value); )*
    t
}};
}

pub fn get_iface_info(s: &str) -> Option<String> {
    let iface_list = datalink::interfaces();
    for iface in iface_list {
        if iface.name == s {
            let ips = &iface.ips;
            return ips.iter()
                .find(|&&ip| ip.is_ipv4())
                .map(|&ip| ip.ip().to_string());
        }
    }

    None
}


pub fn cmd(cmd: &str, args: &[&str]) -> ExitStatus {
    Command::new(cmd)
        .args(args)
        .spawn()
        .expect("fork process error")
        .wait()
        .expect("wait process end error")
}


pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}



#[cfg(test)]
mod tests {
    use super::*;


}
