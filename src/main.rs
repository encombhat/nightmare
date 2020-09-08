use crate::client::VirtualMachineState;
use tokio::time::Duration;

mod client;
mod credentials;
mod device_info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut shadow_client = client::ShadowClient::from_path("./data");

    loop {
        shadow_client.authorize().await?;

        let auth_state = shadow_client.authorization_state();
        use client::AuthState;
        match auth_state {
            AuthState::WaitEmailAndPassword => {
                println!("Main: Loginning in");

                let mut email = String::new();
                std::io::stdin()
                    .read_line(&mut email)
                    .expect("error: unable to read user input");
                email = email.trim().to_string();

                let mut password = String::new();
                std::io::stdin()
                    .read_line(&mut password)
                    .expect("error: unable to read user input");
                password = password.trim().to_string();

                shadow_client.send_email_password(email, password).await;
            }
            AuthState::WaitEmailCode => {
                println!("Main: Waiting code");

                let mut code = String::new();
                std::io::stdin()
                    .read_line(&mut code)
                    .expect("error: unable to read user input");
                code = code.trim().to_string();

                println!("Main: user inputed {}", code);

                shadow_client.send_email_code(code).await?;
            }
            AuthState::Ready => {
                break;
            }
            _ => {}
        }
    }

    println!("Main: finally ready");

    // loop {
    //     let vm_state = shadow_client.fetch_vm_state().await?;
    //     println!("Main: vm state {:?}", vm_state);
    //
    //     match vm_state {
    //         VirtualMachineState::Down => {
    //             shadow_client.start_vm().await?;
    //         }
    //         VirtualMachineState::Up { ip, port } => {
    //             println!("Main: vm ready {}:{}", ip, port);
    //
    //             break;
    //         }
    //         _ => {}
    //     }
    //
    //     tokio::time::delay_for(Duration::from_secs(4)).await;
    // }

    let vm_state = shadow_client.fetch_vm_state().await?;
    println!("Main: vm state {:?}", vm_state);
    shadow_client.start_vm().await?;

    Ok(())
}
