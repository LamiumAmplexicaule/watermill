use std::fs::File;
use std::path::Path;
use std::time::UNIX_EPOCH;
use std::{fs, io};

use async_recursion::async_recursion;
use chrono::{Local, TimeZone};
use csv::Reader;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Vendor {
    #[serde(rename = "Registry")]
    pub(crate) _registry: String,

    #[serde(rename = "Assignment")]
    pub(crate) assignment: String,

    #[serde(rename = "Organization Name")]
    pub(crate) name: String,

    #[serde(rename = "Organization Address")]
    pub(crate) _address: String,
}

impl Vendor {
    #[async_recursion]
    pub async fn new(path: &Path, update_request: bool) -> Vec<Vendor> {
        let file = File::open(path);

        match file {
            Ok(file) => {
                let metadata = file.metadata().unwrap();
                let system_time = metadata.modified().unwrap();
                let unix_time = system_time.duration_since(UNIX_EPOCH).unwrap();
                let local_time = Local.timestamp_opt(unix_time.as_secs() as i64, 0).unwrap();
                let now = Local::now();
                let diff = now - local_time;
                let mut needs_update = false;
                if diff.num_weeks() >= 4 {
                    needs_update = true;
                }
                if update_request || needs_update {
                    Self::get_oui(path).await;
                    Vendor::new(path, false).await;
                }
                let mut reader = Reader::from_reader(file);
                reader
                    .deserialize()
                    .map(|s| s.unwrap())
                    .collect::<Vec<Vendor>>()
            }
            Err(_) => {
                Self::get_oui(path).await;
                Vendor::new(path, false).await
            }
        }
    }

    pub async fn get_oui(path: &Path) {
        let url = "https://standards-oui.ieee.org/oui/oui.csv";
        let response = reqwest::get(url).await.unwrap();
        let bytes = response.bytes().await.unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut out = File::create(path).unwrap();
        io::copy(&mut bytes.as_ref(), &mut out).unwrap();
    }
}
