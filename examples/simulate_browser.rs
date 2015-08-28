// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

extern crate regex;
extern crate routing;
extern crate safe_dns;
extern crate safe_nfs;
extern crate sodiumoxide;
#[macro_use] extern crate safe_client;

const DEFAULT_SERVICE: &'static str = "www";
const HOME_PAGE_FILE_NAME: &'static str = "index.html";

fn handle_login() -> std::sync::Arc<std::sync::Mutex<safe_client::client::Client>> {
    let mut pin = String::new();
    let mut keyword = String::new();
    let mut password = String::new();

    println!("\n\tAccount Creation");
    println!("\t================");

    println!("\n------------ Enter Keyword ---------------");
    let _ = std::io::stdin().read_line(&mut keyword);

    println!("\n\n------------ Enter Password --------------");
    let _ = std::io::stdin().read_line(&mut password);
    loop {
        println!("\n\n--------- Enter PIN (4 Digits) -----------");
        let _ = std::io::stdin().read_line(&mut pin);
        pin = pin.trim().to_string();
        if pin.parse::<u16>().is_ok() && pin.len() == 4 {
            break;
        }
        println!("ERROR: PIN is not 4 Digits !!");
        pin.clear();
    }

    // Account Creation
    {
        println!("\nTrying to create an account ...");
        let _ = eval_result!(safe_client::client::Client::create_account(keyword.clone(), pin.clone(), password.clone()));
        println!("Account Creation Successful !!");
    }

    println!("\n\n\tAuto Account Login");
    println!("\t==================");

    // Log into the created account
    println!("\nTrying to log into the created account using supplied credentials ...");
    std::sync::Arc::new(std::sync::Mutex::new(eval_result!(safe_client::client::Client::log_in(keyword, pin, password))))
}

fn create_dns_record(client        : std::sync::Arc<std::sync::Mutex<safe_client::client::Client>>,
                     dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Create Dns Record");
    println!(    "    =================");
    println!("\nEnter Dns Name (eg., pepsico.com [Note: more than one \".\"s are not allowed in this simple example]):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nGenerating messaging ecryption keys for you...");
    let (public_messaging_encryption_key, secret_messaging_encryption_key) = sodiumoxide::crypto::box_::gen_keypair();

    println!("Registering Dns...");

    let owners = vec![try!(client.lock().unwrap().get_public_signing_key()).clone()];
    let secret_signing_key = try!(client.lock().unwrap().get_secret_signing_key()).clone();
    let dns_struct_data = try!(dns_operations.register_dns(long_name,
                                                           &public_messaging_encryption_key,
                                                           &secret_messaging_encryption_key,
                                                           &vec![],
                                                           owners,
                                                           &secret_signing_key,
                                                           None));
    Ok(client.lock().unwrap().put(routing::data::Data::StructuredData(dns_struct_data), None))
}

fn delete_dns_record(client        : std::sync::Arc<std::sync::Mutex<safe_client::client::Client>>,
                     dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Delete Dns Record");
    println!(    "    =================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    let secret_signing_key = try!(client.lock().unwrap().get_secret_signing_key()).clone();

    println!("Deleting Dns...");

    let dns_struct_data = try!(dns_operations.delete_dns(&long_name, &secret_signing_key));
    Ok(client.lock().unwrap().delete(routing::data::Data::StructuredData(dns_struct_data), None))
}

fn display_dns_records(dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Display Dns Records");
    println!(    "    ===================");
    println!("\nRegistered Dns Names (fetching...):");
    let record_names = try!(dns_operations.get_all_registered_names());
    for it in record_names.iter().enumerate() {
        println!("<{:?}> {}", it.0 + 1, it.1);
    }
    Ok(())
}

fn add_service(client        : std::sync::Arc<std::sync::Mutex<safe_client::client::Client>>,
               dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Add Service");
    println!(    "    ===========");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nEnter Service Name (eg., www):");
    let mut service_name = String::new();
    let _ = std::io::stdin().read_line(&mut service_name);
    service_name = service_name.trim().to_string();

    println!("Creating Home Directory for the Service...");

    let service_home_dir_name = service_name.clone() + "_home_dir";

    let dir_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(client.clone());
    let dir_listing = try!(dir_helper.create(service_home_dir_name,
                                             safe_nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                             vec![],
                                             false,
                                             safe_nfs::AccessLevel::Public,
                                             None));

    let file_helper = safe_nfs::helper::file_helper::FileHelper::new(client.clone());
    let mut writer = try!(file_helper.create(HOME_PAGE_FILE_NAME.to_string(), vec![], dir_listing));

    println!("\nEnter text that you want to display on the Home-Page:");
    let mut text = String::new();
    let _ = std::io::stdin().read_line(&mut text);
    text = text.trim().to_string();

    println!("Creating Home Page for the Service...");

    writer.write(text.as_bytes(), 0);
    let updated_parent_dir_listing = try!(writer.close());
    let dir_key = updated_parent_dir_listing.get_key();

    let secret_signing_key = try!(client.lock().unwrap().get_secret_signing_key()).clone();

    let struct_data = try!(dns_operations.add_service(&long_name,
                                                      (service_name, (dir_key.0.clone(), dir_key.1)),
                                                      &secret_signing_key,
                                                      None));
    Ok(client.lock().unwrap().post(routing::data::Data::StructuredData(struct_data), None))
}

fn remove_service(client        : std::sync::Arc<std::sync::Mutex<safe_client::client::Client>>,
                  dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Remove Service");
    println!(    "    ==============");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nEnter Service Name (eg., www):");
    let mut service_name = String::new();
    let _ = std::io::stdin().read_line(&mut service_name);
    service_name = service_name.trim().to_string();

    println!("Removing Service...");

    let secret_signing_key = try!(client.lock().unwrap().get_secret_signing_key()).clone();
    let struct_data = try!(dns_operations.remove_service(&long_name, service_name, &secret_signing_key, None));
    Ok(client.lock().unwrap().post(routing::data::Data::StructuredData(struct_data), None))
}
 
fn display_services(dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Display Services");
    println!(    "    ================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nServices For Dns {:?} (fetching...):", long_name);
    let service_names = try!(dns_operations.get_all_services(&long_name, None));
    for it in service_names.iter().enumerate() {
        println!("<{:?}> {}", it.0 + 1, it.1);
    }
    Ok(())
}

fn parse_url_and_get_home_page(client        : std::sync::Arc<std::sync::Mutex<safe_client::client::Client>>,
                               dns_operations: &safe_dns::dns_operations::DnsOperations) -> Result<(), safe_dns::errors::DnsError> {
    println!("\n\n    Parse URL");
    println!(    "    =========");
    println!("\nEnter SAFE-Url (eg., safe:lays.pepsico.com ie., \"safe:[<service-name>.]<dns-name>\"):");
    let mut url = String::new();
    let _ = std::io::stdin().read_line(&mut url);
    url = url.trim().to_string();

    let re_with_service = try!(regex::Regex::new(r"safe:([^.]+?)\.([^.]+?\.[^.]+)$").map_err(|_| safe_dns::errors::DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));
    let re_without_service = try!(regex::Regex::new(r"safe:([^.]+?\.[^.]+)$").map_err(|_| safe_dns::errors::DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));

    let long_name;
    let service_name;

    if re_with_service.is_match(&url) {
        let captures = try!(re_with_service.captures(&url).ok_or(safe_dns::errors::DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = try!(captures.at(1).ok_or(safe_dns::errors::DnsError::Unexpected("Could not access a capture !!".to_string())));
        let caps_1 = try!(captures.at(2).ok_or(safe_dns::errors::DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_1.to_string();
        service_name = caps_0.to_string();
    } else if re_without_service.is_match(&url) {
        let captures = try!(re_without_service.captures(&url).ok_or(safe_dns::errors::DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = try!(captures.at(1).ok_or(safe_dns::errors::DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_0.to_string();
        service_name = DEFAULT_SERVICE.to_string();
    } else {
        return Err(safe_dns::errors::DnsError::Unexpected("Malformed Url !!".to_string()))
    }

    println!("Fetching data...");

    let (dir_id, tag_type) = try!(dns_operations.get_service_home_directory_key(&long_name, &service_name, None));
    let direcory_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(client.clone());
    let dir_listing = try!(direcory_helper.get((&dir_id, tag_type), false, &safe_nfs::AccessLevel::Public));

    let file = try!(dir_listing.get_files().iter().find(|a| *a.get_name() == HOME_PAGE_FILE_NAME.to_string())
                                                       .ok_or(safe_dns::errors::DnsError::Unexpected("Could not find homepage !!".to_string())));
    let file_helper = safe_nfs::helper::file_helper::FileHelper::new(client.clone());
    let mut reader = file_helper.read(file);
    let size = reader.size();
    let content = try!(reader.read(0, size));

    println!("\n-----------------------------------------------------");
    println!(  "                 Home Page Contents");
    println!(  "-----------------------------------------------------\n");
    println!("{}", try!(String::from_utf8(content).map_err(|_| safe_dns::errors::DnsError::Unexpected("Cannot convert contents to displayable string !!".to_string()))));

    Ok(())
}

fn main() {
    let client = handle_login();
    println!("Account Login Successful !!");

    println!("Initialising Dns...");
    let dns_operations = eval_result!(safe_dns::dns_operations::DnsOperations::new(client.clone()));

    let mut user_option = String::new();

    loop {
        println!("\n\n     ------\n    | MENU |\n     ------");
        println!("\n<1> Register Your Dns");
        println!("\n<2> Delete Dns Record");
        println!("\n<3> List Dns Records");
        println!("\n<4> Add Service");
        println!("\n<5> Remove Service");
        println!("\n<6> List Services");
        println!("\n<7> Parse URL (Simulate Browser)");
        println!("\n<8> Exit");

        println!("\nEnter Option [1-8]:");
        let _ = std::io::stdin().read_line(&mut user_option);

        if let Ok(option) = user_option.trim().parse::<u8>() {
            let mut error = None;

            match option {
                1 => if let Err(err) = create_dns_record(client.clone(), &dns_operations) {
                    error = Some(err);
                },
                2 => if let Err(err) = delete_dns_record(client.clone(), &dns_operations) {
                    error = Some(err);
                },
                3 => if let Err(err) = display_dns_records(&dns_operations) {
                    error = Some(err);
                },
                4 => if let Err(err) = add_service(client.clone(), &dns_operations) {
                    error = Some(err);
                },
                5 => if let Err(err) = remove_service(client.clone(), &dns_operations) {
                    error = Some(err);
                },
                6 => if let Err(err) = display_services(&dns_operations) {
                    error = Some(err);
                },
                7 => if let Err(err) = parse_url_and_get_home_page(client.clone(), &dns_operations) {
                    error = Some(err);
                },
                8 => break,
                _ => println!("\nUnrecognised option !!"),
            }

            println!("\n ----------------------------------------------");
            if let Some(err) = error {
                println!("|  ERROR !! {:?}", err);
            } else {
                println!("|  Operation Completed Successfully !");
            }
            println!(" ----------------------------------------------");
        } else {
            println!("\nUnrecognised option !!");
        }

        println!("Hit Enter to continue...");
        let _ = std::io::stdin().read_line(&mut user_option);
        user_option.clear();
    }
}
