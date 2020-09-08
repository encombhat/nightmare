use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CredsData {
    pub device_id: String, // Also x-shadow-uuid

    pub email: String,

    pub refresh: String,
    pub token: String,
}

pub struct Credentials {
    data: Arc<Mutex<Option<CredsData>>>,
}

impl Credentials {
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Self {
        let config_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_path)
            .expect("file should open read only");
        if let Ok(credentials) = serde_json::from_reader::<_, CredsData>(config_file) {
            return Self {
                data: Arc::new(Mutex::new(Some(credentials))),
            };
        }

        Self {
            data: Arc::new(Mutex::new(None)),
        }
    }

    pub fn to_file<P: AsRef<Path>>(&self, file_path: P) {
        let data_opt = self.data.lock().unwrap();

        if let Some(data) = data_opt.as_ref() {
            let creds_file = std::fs::OpenOptions::new()
                .write(true)
                .open(file_path)
                .expect("file should open read/write");
            serde_json::to_writer(creds_file, data)
                .expect("achievement unlocked: how did we get here?");
        }
    }

    pub fn device_id(&self) -> Option<String> {
        self.data.lock().unwrap().clone().map(|d| d.device_id)
    }

    pub fn email(&self) -> Option<String> {
        self.data.lock().unwrap().clone().map(|d| d.email)
    }

    pub fn token(&self) -> Option<String> {
        self.data.lock().unwrap().clone().map(|d| d.token)
    }

    pub fn refresh(&self) -> Option<String> {
        self.data.lock().unwrap().clone().map(|d| d.refresh)
    }

    pub fn set_credentials(
        &self,
        device_id: String,
        email: String,
        token: String,
        refresh: String,
    ) {
        let mut data_opt = self.data.lock().unwrap();

        let creds_data = CredsData {
            device_id,
            email,
            refresh,
            token,
        };
        *data_opt = Some(creds_data);
    }
}
