use std::future::pending;
use zbus::{connection, interface, zvariant, proxy};
use std::collections::HashMap;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::{thread};
use async_std::task;
use shielded::Shielded;
use std::sync::Mutex;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

struct MySecretService {
    items: Mutex<Shielded>,
    rx: Mutex<Receiver<HashMap<String, String>>>
}

static mut TX: Option<Sender<HashMap<String, String>>> = None;

fn gen_rand_string() -> String {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    rand_string
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl MySecretService {
    fn update_items(&mut self, items: Vec<HashMap<String,String>>) {
        if items.len() < 1 {
            return;
        }
        let newbytes = {
            let mut shielded_blob = self.items.lock().unwrap();
            let unshielded = (*shielded_blob).unshield();
            let bytes = unshielded.as_ref();
            let s = match std::str::from_utf8(bytes) {
                Ok(v) => v,
                Err(e) => {
                    println!("UpdateItems: Invalid UTF-8 sequence: {}", e);
                    "{}"
                },
            };
            let mut old_values: HashMap<String, String> = match serde_json::from_str(s) {
                Ok(v) => v,
                Err(e) => {
                    println!("UpdateItems: Unable to convert old shielded data to HashMap: {}", e);
                    HashMap::new()
                },
            };
            for new_val in items.iter() {
                for (key, value) in new_val.into_iter() {
                    old_values.insert((*key).to_string(), (*value).to_string());
                }
            }
            let news = match serde_json::to_string::<HashMap<String,String>>(&old_values) {
                Ok(v) => v,
                Err(e) => {
                    println!("UpdateItems: Unable to generate new JSON string: {}", e);
                    s.to_string()
                },
            };
            news.as_bytes().to_vec()
        };
        self.items = Mutex::new(Shielded::new(newbytes));
    }
    fn update_values(&mut self) {
        let mut new_items : Vec<HashMap<String,String>> = vec![];
        let mut counter : usize = 0;
        {
            let rx = self.rx.lock().unwrap();
            let mut iter = (*rx).try_iter();
            loop {
                let val = match iter.next() {
                    Some(v) => v,
                    None => {
                        break;
                    },
                };
                counter = counter + val.len();
                new_items.push(val);
            }
        }
        println!("UpdateValues: {} new items will be added", counter);
        self.update_items(new_items);
    }
    fn has_value(&mut self, searched: String) -> bool {
        let mut shielded_blob = self.items.lock().unwrap();
        let unshielded = (*shielded_blob).unshield();
        let bytes = unshielded.as_ref();
        let s = match std::str::from_utf8(bytes) {
            Ok(v) => v,
            Err(e) => {
                println!("HasValue: Invalid UTF-8 sequence: {}", e);
                "{}"
            },
        };
        let old_values: HashMap<String, String> = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                println!("HasValue: Unable to convert old shielded data to HashMap: {}", e);
                HashMap::new()
            },
        };
        match old_values.get(&searched) {
            Some(_v) => true,
            None => false,
        }
    }
    fn get_value(&mut self, searched: String) -> String {
        let mut shielded_blob = self.items.lock().unwrap();
        let unshielded = (*shielded_blob).unshield();
        let bytes = unshielded.as_ref();
        let s = match std::str::from_utf8(bytes) {
            Ok(v) => v,
            Err(e) => {
                println!("GetValue: Invalid UTF-8 sequence: {}", e);
                "{}"
            },
        };
        let old_values: HashMap<String, String> = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                println!("GetValue: Unable to convert old shielded data to HashMap: {}", e);
                HashMap::new()
            },
        };
        match old_values.get(&searched) {
            Some(v) => (*v).to_string(),
            None => "".to_string(),
        }
    }
    fn open_session(&mut self, algorithm: &str, _input: zvariant::OwnedValue) -> zbus::fdo::Result<(zvariant::OwnedValue, zvariant::OwnedObjectPath)> {
        if algorithm != "plain" {
            println!("OpenSession: Rejecting algorithm {}", algorithm);
            return Err(zbus::fdo::Error::NotSupported("Another algorithm, please".to_string()));
        }
        let session_path_str = format!("/org/freedesktop/secrets/session/{}", gen_rand_string());
        let session_path = match zvariant::OwnedObjectPath::try_from(session_path_str.to_string()) {
            Ok(v) => v,
            Err(e) => {
                println!("OpenSession: Unable to generate a sessions ID for {}: {}", session_path_str, e);
                return Err(zbus::fdo::Error::Failed("Unable to generate a session ID".to_string()));
            }
        };
        println!("OpenSession: new session with path: {}", session_path_str);
        Ok((zvariant::OwnedValue::from(zvariant::Str::from("plain")), session_path))
    }
    fn search_items(&mut self, attributes: HashMap<String,String>) -> zbus::fdo::Result<(Vec<zvariant::OwnedObjectPath>, Vec<zvariant::OwnedObjectPath>)> {
        for (_key, value) in attributes.into_iter() {
            if self.has_value(value.to_string()) {
                let oop = match zvariant::OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/default/{}", value)) {
                    Ok(v) => v,
                    Err(e) => {
                        println!("SearchItems: Unable to convert item to OwnedObjectPath {}: {}", value, e);
                        return Err(zbus::fdo::Error::Failed("Unable to find a valid entry".to_string()));
                    }
                };
                return Ok((vec![oop], vec![]));
            }
        }
        return Err(zbus::fdo::Error::FileNotFound("Unable to find a valid entry".to_string()));
    }
    fn get_secrets(&mut self, items: Vec<zvariant::OwnedObjectPath>, session: zvariant::OwnedObjectPath) -> zbus::fdo::Result<HashMap<zvariant::OwnedObjectPath, (zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String)>> {
        let mut map : HashMap<zvariant::OwnedObjectPath, (zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String)> = HashMap::new();
        for searched in items.iter() {
            let searched_str = searched.as_str();
            if !searched_str.starts_with("/org/freedesktop/secrets/collection/default/") {
                continue;
            }
            let searched_str = &searched_str["/org/freedesktop/secrets/collection/default/".len()..];
            if !self.has_value(searched_str.to_string()) {
                continue;
            }
            let my_string = self.get_value(searched_str.to_string());
            let bytes: Vec<u8> = my_string.into_bytes();
            map.insert(searched.clone(), (session.clone(), vec![], bytes, "text/plain".to_string()));
        }
        Ok(map)
    }
}

#[proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait MySecretServiceTrigger {
    async fn update_values(&mut self) -> zbus::Result<()>;
}

async fn launch_dbus_listener() {
    let (tx, rx): (Sender<HashMap<String,String>>, Receiver<HashMap<String,String>>) = mpsc::channel();
    unsafe {
        TX = Some(tx);
    }
    let myss = MySecretService{items: Mutex::new(Shielded::new(vec![])), rx: Mutex::new(rx)};
    let _conn = connection::Builder::session().unwrap()
        .name("org.freedesktop.secrets").unwrap()
        .serve_at("/org/freedesktop/secrets", myss).unwrap()
        .build()
        .await.unwrap();

    // Do other things or go to wait forever
    pending::<()>().await;
}

fn update_entries_from_map(new_values: HashMap<String,String>) {
    unsafe {
        match &TX {
            Some(ttx) => {
                let _ = ttx.send(new_values);
            },
            None => {},
        };
    }
    let future = async move {
        let connection = zbus::Connection::session().await.unwrap();
        let mut proxy = MySecretServiceTriggerProxy::new(&connection).await.unwrap();
        let _ = proxy.update_values().await.unwrap();
    };
    task::block_on(future);
}

pub fn update_entries(items: String) {
    println!("UpdateEntries (Rust): received new data");
    let new_values: HashMap<String, String> = match serde_json::from_str(&items) {
        Ok(v) => v,
        Err(e) => {
            println!("UpdateEntries (Rust): Unable to convert new data to HashMap: {}", e);
            return;
        },
    };
    update_entries_from_map(new_values);
}

pub fn start_dbus() {
    let thread_handle = thread::spawn(|| {
        let future = async move {
            launch_dbus_listener().await
        };
        task::block_on(future);
    });
    thread_handle.join().unwrap();
}
