use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{de, Deserialize, Deserializer, Serialize};
use url::Url;

use crate::credentials::Credentials;
use crate::device_info::DeviceInfo;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum VirtualMachineState {
    Unknown,

    Down,
    Starting,
    Up { ip: String, port: u16 },
}

#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum AuthState {
    Unknown,

    WaitEmailAndPassword,
    WaitEmailCode,

    Ready,
}

#[derive(Clone)]
struct GapSession {
    gap_url: Url,
    gap_token: String,
}

pub struct ShadowClient {
    config_path: PathBuf,

    creds: Credentials,
    auth_state: Arc<Mutex<AuthState>>,
    gap_session: Arc<Mutex<Option<GapSession>>>,

    http_client: reqwest::Client,
}

impl ShadowClient {
    const SSO_API_URL: &'static str = "https://sso.api-web.shadow.tech/api/v2";
    const TINAG_URL: &'static str = "https://tinag.shadow.tech/gap";

    const HEADER_X_SHADOW_UUID: &'static str = "X-Shadow-Uuid";

    const CREDS_FILENAME: &'static str = "creds.json";

    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        std::fs::create_dir_all(path.as_ref()).unwrap();

        let creds = Credentials::from_file(path.as_ref().to_path_buf().join(Self::CREDS_FILENAME));

        Self {
            config_path: path.as_ref().to_path_buf(),

            auth_state: Arc::new(Mutex::new(AuthState::Unknown)),
            creds,
            gap_session: Arc::new(Mutex::new(None)),

            http_client: reqwest::ClientBuilder::new()
                .user_agent("Nightmare-0.0.1")
                .build()
                .expect("task failed successfully"),
        }
    }

    pub fn authorization_state(&self) -> AuthState {
        self.auth_state.lock().unwrap().clone()
    }

    pub async fn authorize(&self) -> Result<(), Box<dyn Error>> {
        let mut auth_state = self.auth_state.lock().unwrap();

        if self.creds.device_id().is_none() {
            *auth_state = AuthState::WaitEmailAndPassword;

            return Ok(());
        }
        let device_id = self.creds.device_id().unwrap();

        if self.gap_session.lock().unwrap().is_none() {
            let email = self.creds.email().unwrap();
            let token = self.creds.token().unwrap();

            let gap_url = {
                #[derive(Debug, Deserialize)]
                struct Response {
                    uri: url::Url,
                }

                let response = self
                    .http_client
                    .get(Self::TINAG_URL)
                    .query(&[("email", email.as_str()), ("fmt", "json")])
                    .send()
                    .await?
                    .json::<Response>()
                    .await?;

                response.uri
            };
            println!("Got gap url: {}", gap_url);

            let gap_token = {
                #[derive(Debug, Serialize)]
                struct Request {
                    token: String,
                }
                #[derive(Debug, Deserialize)]
                struct Response {
                    token: String,
                }

                let mut api_url = gap_url.clone();
                api_url.set_path("shadow/auth_login");
                let response = self
                    .http_client
                    .post(api_url)
                    .header(Self::HEADER_X_SHADOW_UUID, &device_id)
                    .json(&Request { token })
                    .send()
                    .await?
                    .json::<Response>()
                    .await?;

                response.token
            };
            println!("Got gap token: {}", gap_token);

            let mut gap_session = self.gap_session.lock().unwrap();
            *gap_session = Some(GapSession { gap_url, gap_token });
        }

        // Otherwise multiple emails
        if *auth_state != AuthState::WaitEmailCode {
            let (gap_url, gap_token) = {
                let gap_session = self.gap_session.lock().unwrap().clone().unwrap();
                (gap_session.gap_url, gap_session.gap_token)
            };

            let mut api_url = gap_url.clone();
            api_url.set_path("shadow/auth_uuid");
            let response = self
                .http_client
                .get(api_url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Token {}", gap_token),
                )
                .header(Self::HEADER_X_SHADOW_UUID, &device_id)
                .send()
                .await?;

            let status_code = response.status();
            if status_code == reqwest::StatusCode::OK {
                println!("Authorized without email 2fa");

                *auth_state = AuthState::Ready;
            } else if status_code == reqwest::StatusCode::PRECONDITION_FAILED {
                println!("Device not registered, check your email");

                *auth_state = AuthState::WaitEmailCode;
            } else {
                println!("Unknown status while checking uuid: {}", status_code);
            }
        }

        Ok(())
    }

    pub async fn send_email_password(
        &self,
        email: String,
        password: String,
    ) -> Result<(), Box<dyn Error>> {
        let device_id = DeviceInfo::default().hash();

        #[derive(Debug, Serialize)]
        struct Request {
            pub device_id: String,
            pub email: String,
            pub password: String,
        }
        #[derive(Debug, Deserialize)]
        struct Response {
            pub refresh: String,
            pub token: String,
        }

        let response = self
            .http_client
            .post(format!("{}/{}", Self::SSO_API_URL, "sso/auth/login").as_str())
            .json(&Request {
                device_id: device_id.clone(),
                email: email.clone(),
                password,
            })
            .send()
            .await?
            .json::<Response>()
            .await?;

        self.creds
            .set_credentials(device_id, email, response.token, response.refresh);
        self.creds
            .to_file(self.config_path.clone().join(Self::CREDS_FILENAME));

        println!(
            "Logged in: {} {}",
            self.creds.email().unwrap(),
            self.creds.token().unwrap()
        );

        Ok(())
    }

    pub async fn send_email_code(&self, code: String) -> Result<(), Box<dyn Error>> {
        if self.authorization_state() != AuthState::WaitEmailCode {
            return Ok(());
        }

        println!("Sending code: {}", code);

        let (gap_url, gap_token) = {
            let gap_session = self.gap_session.lock().unwrap().clone().unwrap();
            (gap_session.gap_url, gap_session.gap_token)
        };
        let device_id = self.creds.device_id().unwrap();
        let mut auth_state = self.auth_state.lock().unwrap();

        {
            let mut api_url = gap_url.clone();
            api_url.set_path("shadow/client/approval");
            let response = self
                .http_client
                .get(api_url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Token {}", gap_token),
                )
                .header(Self::HEADER_X_SHADOW_UUID, &device_id)
                .query(&[("code", code.as_str())])
                .send()
                .await?;

            let status_code = response.status();
            if status_code == reqwest::StatusCode::OK {
                println!("Email code accepted");

                *auth_state = AuthState::Ready;
            } else if status_code == reqwest::StatusCode::FORBIDDEN {
                println!("Email code incorrect");

                *auth_state = AuthState::WaitEmailCode;
            } else {
                println!("Unknown status while sending email code: {}", status_code);
            }
        }

        Ok(())
    }

    pub async fn fetch_vm_state(&self) -> Result<VirtualMachineState, Box<dyn Error>> {
        if self.authorization_state() != AuthState::Ready {
            return Ok(VirtualMachineState::Unknown);
        }

        let (gap_url, gap_token) = {
            let gap_session = self.gap_session.lock().unwrap().clone().unwrap();
            (gap_session.gap_url, gap_session.gap_token)
        };
        let device_id = self.creds.device_id().unwrap();

        #[derive(Debug, Deserialize)]
        struct Response {
            pub ip: String,
            #[serde(deserialize_with = "from_str")]
            pub port: u16,
        }

        fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: FromStr,
            T::Err: Display,
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            T::from_str(&s).map_err(|e| de::Error::custom(format!("not a number")))
        }

        let mut api_url = gap_url.clone();
        api_url.set_path("shadow/vm/ip");
        let response = self
            .http_client
            .get(api_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Token {}", gap_token),
            )
            .header(Self::HEADER_X_SHADOW_UUID, &device_id)
            .send()
            .await?;

        let vm_state_code = match response.status().as_u16() {
            200 => {
                let response_body = response.json::<Response>().await?;
                VirtualMachineState::Up {
                    ip: response_body.ip,
                    port: response_body.port,
                }
            }
            429 | 470 | 471 | 472 => VirtualMachineState::Down,
            473 => VirtualMachineState::Starting,
            _ => VirtualMachineState::Unknown,
        };

        Ok(vm_state_code)
    }

    pub async fn start_vm(&self) -> Result<(), Box<dyn Error>> {
        if self.authorization_state() != AuthState::Ready {
            return Ok(());
        }

        let (gap_url, gap_token) = {
            let gap_session = self.gap_session.lock().unwrap().clone().unwrap();
            (gap_session.gap_url, gap_session.gap_token)
        };
        let device_id = self.creds.device_id().unwrap();

        let mut api_url = gap_url.clone();
        api_url.set_path("shadow/vm/start");
        let response = self
            .http_client
            .get(api_url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Token {}", gap_token),
            )
            .header(Self::HEADER_X_SHADOW_UUID, &device_id)
            .send()
            .await?;

        let status_code = response.status();
        if status_code == reqwest::StatusCode::OK {
            println!("Starting vm called");
        }

        Ok(())
    }
}
