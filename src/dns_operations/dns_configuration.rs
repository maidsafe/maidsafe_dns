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

use std::sync::{Arc, Mutex};

use sodiumoxide::crypto::box_;

use errors::DnsError;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use safe_core::client::Client;
use safe_nfs::errors::NfsError::FileAlreadyExistsWithSameName;
use safe_nfs::helper::directory_helper::DirectoryHelper;
use safe_nfs::helper::file_helper::FileHelper;
use safe_nfs::helper::writer::Mode;

const DNS_CONFIG_DIR_NAME: &'static str = "DnsReservedDirectory";
const DNS_CONFIG_FILE_NAME: &'static str = "DnsConfigurationFile";

#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfiguation {
    pub long_name: String,
    pub encryption_keypair: (box_::PublicKey, box_::SecretKey),
}

pub fn initialise_dns_configuaration(client: Arc<Mutex<Client>>) -> Result<(), DnsError> {
    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        try!(dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string()));
    let file_helper = FileHelper::new(client.clone());
    match file_helper.create(DNS_CONFIG_FILE_NAME.to_string(), vec![], dir_listing) {
        Ok(writer) => {
            let _ = try!(writer.close());
            Ok(())
        }
        Err(FileAlreadyExistsWithSameName) => Ok(()),
        Err(error) => Err(DnsError::from(error)),
    }
}

pub fn get_dns_configuaration_data(client: Arc<Mutex<Client>>)
                                   -> Result<Vec<DnsConfiguation>, DnsError> {
    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        try!(dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string()));
    let file = try!(dir_listing.get_files()
                               .iter()
                               .find(|file| file.get_name() == DNS_CONFIG_FILE_NAME)
                               .ok_or(DnsError::DnsConfigFileNotFoundOrCorrupted));
    let file_helper = FileHelper::new(client.clone());
    debug!("Reading dns configuration data from file ...");
    let mut reader = file_helper.read(file);
    let size = reader.size();
    if size != 0 {
        Ok(try!(deserialise(&try!(reader.read(0, size)))))
    } else {
        Ok(vec![])
    }
}

pub fn write_dns_configuaration_data(client: Arc<Mutex<Client>>,
                                     config: &Vec<DnsConfiguation>)
                                     -> Result<(), DnsError> {
    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        try!(dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string()));
    let file = try!(dir_listing.get_files()
                               .iter()
                               .find(|file| file.get_name() == DNS_CONFIG_FILE_NAME)
                               .ok_or(DnsError::DnsConfigFileNotFoundOrCorrupted))
                   .clone();
    let file_helper = FileHelper::new(client.clone());
    let mut writer = try!(file_helper.update_content(file, Mode::Overwrite, dir_listing));
    debug!("Writing dns configuration data ...");
    writer.write(&try!(serialise(&config)), 0);
    let _ = try!(writer.close());
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{Arc, Mutex};
    use sodiumoxide::crypto::box_;
    use safe_core::utility::{self, test_utils};

    #[test]
    fn read_write_dns_configuration_file() {
        let client = Arc::new(Mutex::new(unwrap_result!(test_utils::get_client())));

        // Initialise Dns Configuration File
        unwrap_result!(initialise_dns_configuaration(client.clone()));

        // Get the Stored Configurations
        let mut config_vec = unwrap_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);

        let long_name = unwrap_result!(utility::generate_random_string(10));

        // Put in the 1st record
        let mut keypair = box_::gen_keypair();
        let config_0 = DnsConfiguation {
            long_name: long_name.clone(),
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec.push(config_0.clone());
        unwrap_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert_eq!(config_vec[0], config_0);

        // Modify the content
        keypair = box_::gen_keypair();
        let config_1 = DnsConfiguation {
            long_name: long_name,
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec[0] = config_1.clone();
        unwrap_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert!(config_vec[0] != config_0);
        assert_eq!(config_vec[0], config_1);

        // Delete Record
        config_vec.clear();
        unwrap_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);
    }
}
