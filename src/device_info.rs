use sha3::{Digest, Sha3_256};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DeviceInfo {
    hostname: String,

    cpu_count: u32,
    cpu_clock: u64,

    os_type: String,
    os_release: String,
}

impl DeviceInfo {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            hostname: sys_info::hostname()?,

            cpu_count: sys_info::cpu_num()?,
            cpu_clock: sys_info::cpu_speed()?,

            os_type: sys_info::os_type()?,
            os_release: sys_info::os_release()?,
        })
    }

    pub fn hash(&self) -> String {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("I have a time machine");

        let feature_str = format!(
            "{} {} {} SMP #{}@{} TIME {}",
            self.os_type,
            self.hostname,
            self.os_release,
            self.cpu_count,
            self.cpu_clock,
            current_time.as_secs()
        );

        data_encoding::HEXUPPER.encode(Sha3_256::digest(feature_str.as_bytes()).as_ref())
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
