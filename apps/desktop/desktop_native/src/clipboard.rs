use anyhow::Result;

#[cfg(target_os = "windows")]
#[cfg(target_os = "macos")]
use arboard::{Clipboard, Set};

#[cfg(target_os = "linux")]
use arboard::{Clipboard};
use wl_clipboard_rs::copy::{MimeType, MimeSource, Options, Source, ClipboardType};
use std::{thread, time};

pub fn read() -> Result<String> {
    let mut clipboard = Clipboard::new()?;

    Ok(clipboard.get_text()?)
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "macos")]
pub fn write(text: &str, password: bool) -> Result<()> {
    let mut clipboard = Clipboard::new()?;

    let set = clipboard_set(clipboard.set(), password);

    set.text(text)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn write(text: &str, _password: bool) -> Result<()> {
    let mut opts = Options::new();
    opts.clipboard(ClipboardType::Both);
    opts.copy_multi(vec![MimeSource { source: Source::Bytes(text.to_string().into_bytes().into()),
                                  mime_type: MimeType::Autodetect },
                         MimeSource { source: Source::Bytes("secret".to_string().into_bytes().into()),
                                  mime_type: MimeType::Specific("x-kde-passwordManagerHint".to_string()) }])?;
    let ten_millis = time::Duration::from_millis(50);
    thread::sleep(ten_millis);
    Ok(())
}

// Exclude from windows clipboard history
#[cfg(target_os = "windows")]
fn clipboard_set(set: Set, password: bool) -> Set {
    use arboard::SetExtWindows;

    if password {
        set.exclude_from_cloud().exclude_from_history()
    } else {
        set
    }
}

#[cfg(target_os = "macos")]
fn clipboard_set(set: Set, _password: bool) -> Set {
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(feature = "manual_test", not(target_os = "linux")))]
    fn test_write_read() {
        let message = "Hello world!";

        write(message, false).unwrap();
        assert_eq!(message, read().unwrap());
    }
}
