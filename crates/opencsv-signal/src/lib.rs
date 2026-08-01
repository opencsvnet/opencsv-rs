//! Signal transport for OpenCSV consignments.
//!
//! This crate links the OpenCSV client to an existing personal Signal
//! account as a **secondary (linked) device**, like Signal Desktop, using
//! [presage](https://github.com/whisperfish/presage). Consignment blobs
//! travel as ordinary Signal attachments; verification stays client-side in
//! the wallet — Signal only moves opaque bytes.
//!
//! - [`link`] runs the provisioning flow (prints the `tsdevice://` URI as a
//!   terminal QR code, waits for the phone scan) and persists the
//!   registration; on later runs it just loads it.
//! - [`send_consignment`] uploads a blob as an `opencsv-consignment.bin`
//!   attachment with an [`CONSIGNMENT_BODY`][msg::CONSIGNMENT_BODY] marker
//!   body and sends it to a [`Recipient`] (`self` = Note to Self).
//! - [`listen`] streams incoming messages and hands every consignment
//!   attachment to a caller-supplied verifier closure; other messages are
//!   acknowledged and ignored.
//!
//! The crate is deliberately wallet-free: `listen` takes a closure instead
//! of a `Wallet` so the dependency direction stays one way
//! (`opencsv-cli` → `opencsv-signal`).
//!
//! **Prototype-grade.** The sqlite store holds unencrypted Signal session
//! keys and long-term identity keys. Do not point this at an account whose
//! compromise you could not tolerate.

mod error;
pub mod msg;

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::oneshot;
use futures::{future, pin_mut, StreamExt};
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::content::{Content, ContentBody, DataMessage};
use presage::libsignal_service::protocol::ServiceId;
use presage::libsignal_service::sender::AttachmentSpec;
use presage::manager::Registered;
use presage::model::messages::Received;
use presage::proto::sync_message::Sent;
use presage::proto::SyncMessage;
use presage::store::ContentsStore;
use presage::Manager;
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

pub use error::Error;
pub use msg::{
    address_announcement, parse_address, Recipient, ADDRESS_MARKER, CONSIGNMENT_BODY,
    CONSIGNMENT_CONTENT_TYPE, CONSIGNMENT_FILENAME,
};
pub use msg::{is_consignment_attachment, parse_recipient};

/// A registered Signal client backed by the sqlite store.
pub type SignalManager = Manager<SqliteStore, Registered>;

/// File name of the presage sqlite store inside the store directory.
pub const STORE_FILE: &str = "signal.db";

/// How long [`sync_once`] waits for the pending-message queue to drain.
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Link this client to the user's Signal account as a secondary device.
///
/// Prints the provisioning URI both as a terminal QR code (scan with the
/// phone: Signal → Settings → Linked Devices → Link New Device) and as
/// text, then blocks until the phone completes the link. The registration
/// is persisted in `store_dir`; if the store is already registered, the
/// existing registration is loaded and returned instead of re-linking.
pub async fn link(store_dir: &Path, device_name: &str) -> Result<SignalManager, Error> {
    if let Ok(manager) = open(store_dir).await {
        let data = manager.registration_data();
        println!(
            "already linked as {} (device id {:?}); delete {} to re-link",
            data.phone_number,
            data.device_id,
            store_dir.join(STORE_FILE).display()
        );
        return Ok(manager);
    }

    let store = open_store(store_dir).await?;
    let (tx, rx) = oneshot::channel();
    let (result, _) = future::join(
        Manager::link_secondary_device(
            store,
            SignalServers::Production,
            device_name.to_string(),
            tx,
        ),
        async move {
            match rx.await {
                Ok(url) => {
                    println!(
                        "on your phone: Signal → Settings → Linked Devices → Link New Device, then scan:"
                    );
                    if let Err(e) = qr2term::print_qr(url.to_string()) {
                        eprintln!("(could not render the QR code: {e})");
                    }
                    println!("provisioning URI (if the QR code is unreadable):");
                    println!("{url}");
                    println!("waiting for the phone to finish linking…");
                }
                Err(_) => eprintln!("provisioning channel closed before the URI arrived"),
            }
        },
    )
    .await;

    let manager = result.map_err(|e| Error::Signal(format!("linking failed: {e}")))?;
    let data = manager.registration_data();
    println!(
        "linked as {} (device id {:?}), store at {}",
        data.phone_number,
        data.device_id,
        store_dir.join(STORE_FILE).display()
    );
    Ok(manager)
}

/// Load an existing registration from `store_dir`.
///
/// Fails with [`Error::NotRegistered`] if [`link`] has never completed here.
pub async fn open(store_dir: &Path) -> Result<SignalManager, Error> {
    let store = open_store(store_dir).await?;
    Manager::load_registered(store).await.map_err(|e| {
        eprintln!("(load_registered said: {e})");
        Error::NotRegistered
    })
}

/// Drain the pending message queue once (sessions, profile keys, contacts).
///
/// Recommended before sending: outbound messages can be rejected by the
/// recipient if session state updates sit unprocessed in the queue.
pub async fn sync_once(manager: &mut SignalManager) -> Result<(), Error> {
    let drain = async {
        let messages = manager
            .receive_messages()
            .await
            .map_err(|e| Error::Signal(format!("could not open message stream: {e}")))?;
        pin_mut!(messages);
        while let Some(item) = messages.next().await {
            match item {
                Received::QueueEmpty => break,
                Received::Content(_) | Received::Contacts | Received::DecryptionError(_) => {}
            }
        }
        Ok(())
    };
    match tokio::time::timeout(SYNC_TIMEOUT, drain).await {
        Ok(result) => result,
        Err(_) => Err(Error::Signal(format!(
            "message queue did not drain within {}s",
            SYNC_TIMEOUT.as_secs()
        ))),
    }
}

/// Resolve a [`Recipient`] to a Signal [`ServiceId`].
///
/// Phone numbers are resolved against the contacts synced from the primary
/// device; a number that is not in the synced contacts cannot be resolved
/// (use the ACI uuid instead).
pub async fn resolve_recipient(
    manager: &SignalManager,
    recipient: &Recipient,
) -> Result<ServiceId, Error> {
    match recipient {
        Recipient::SelfNote => Ok(manager.registration_data().service_ids.aci().into()),
        Recipient::Aci(uuid) => Ok(ServiceId::Aci((*uuid).into())),
        Recipient::Phone(phone) => {
            let contacts = manager
                .store()
                .contacts()
                .await
                .map_err(|e| Error::Signal(format!("could not read contacts: {e}")))?;
            for contact in contacts {
                let contact =
                    contact.map_err(|e| Error::Signal(format!("could not read contact: {e}")))?;
                if contact.phone_number.as_ref() == Some(phone) {
                    return Ok(ServiceId::Aci(contact.uuid.into()));
                }
            }
            Err(Error::Recipient(format!(
                "no synced contact with phone number {phone}; pass the recipient's ACI uuid instead"
            )))
        }
    }
}

/// Send a consignment blob as a Signal attachment.
///
/// The blob is uploaded under [`CONSIGNMENT_FILENAME`] with content type
/// [`CONSIGNMENT_CONTENT_TYPE`] and a short marker body, so the receiving
/// side can recognise it with [`is_consignment_attachment`].
pub async fn send_consignment(
    manager: &mut SignalManager,
    recipient: &Recipient,
    blob: &[u8],
    sender_address: Option<&str>,
) -> Result<(), Error> {
    let service_id = resolve_recipient(manager, recipient).await?;

    let spec = AttachmentSpec {
        content_type: CONSIGNMENT_CONTENT_TYPE.to_string(),
        length: blob.len(),
        file_name: Some(CONSIGNMENT_FILENAME.to_string()),
        preview: None,
        voice_note: None,
        borderless: None,
        width: None,
        height: None,
        caption: None,
        blur_hash: None,
    };
    let mut uploads = manager
        .upload_attachments(vec![(spec, blob.to_vec())])
        .await
        .map_err(|e| Error::Signal(format!("attachment upload failed: {e}")))?;
    let pointer = uploads
        .pop()
        .expect("one upload was requested")
        .map_err(|e| Error::Attachment(format!("upload rejected: {e:?}")))?;

    let mut body = format!("{CONSIGNMENT_BODY} ({} bytes)", blob.len());
    if let Some(address) = sender_address {
        // Carry the sender's receiving key so the recipient's wallet can
        // prefill the reply-to address from the chat itself.
        body.push('\n');
        body.push_str(&msg::address_announcement(address));
    }
    let message = DataMessage {
        body: Some(body),
        attachments: vec![pointer],
        ..Default::default()
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_millis() as u64;
    manager
        .send_message(service_id, message, timestamp)
        .await
        .map_err(|e| Error::Signal(format!("send failed: {e}")))?;
    Ok(())
}

/// Send a plain text message (used for address announcements).
pub async fn send_text(
    manager: &mut SignalManager,
    recipient: &Recipient,
    body: &str,
) -> Result<(), Error> {
    let service_id = resolve_recipient(manager, recipient).await?;
    let message = DataMessage {
        body: Some(body.to_string()),
        ..Default::default()
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_millis() as u64;
    manager
        .send_message(service_id, message, timestamp)
        .await
        .map_err(|e| Error::Signal(format!("send failed: {e}")))?;
    Ok(())
}

/// Stream incoming messages until Ctrl-C.
///
/// Every attachment that looks like a consignment (see
/// [`is_consignment_attachment`]) is downloaded and handed to
/// `on_consignment`, whose returned string is printed as the verdict (the
/// CLI's closure runs `opencsv_cli::ops::receive` and returns
/// `VERIFIED …` / `REJECTED …`). Messages that are not consignments are
/// acknowledged with one line and otherwise ignored.
pub async fn listen<F>(manager: &mut SignalManager, mut on_consignment: F) -> Result<(), Error>
where
    F: FnMut(&[u8]) -> String,
{
    println!("listening for OpenCSV consignments (Ctrl-C to stop)…");
    // `receive_messages` yields a finite stream: it ends once the backlog is
    // drained (and whenever the websocket drops). Re-open it in a loop so the
    // listener stays alive for new messages.
    'outer: loop {
        let messages = match manager.receive_messages().await {
            Ok(messages) => messages,
            Err(e) => {
                println!("could not open message stream ({e}); retrying in 5s…");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break 'outer,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue 'outer,
                }
            }
        };
        pin_mut!(messages);
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("Ctrl-C received, stopping");
                    break 'outer;
                }
                item = messages.next() => {
                    let Some(item) = item else {
                        // Stream ended (backlog drained / connection closed);
                        // re-open to keep listening.
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue 'outer;
                    };
                    match item {
                        Received::QueueEmpty => {
                            println!("message queue drained; waiting for new messages…");
                        }
                        Received::Contacts => println!("contacts synced from primary device"),
                        Received::DecryptionError(id) => {
                            println!("could not decrypt a message from {id:?} (a session reset may fix this)");
                        }
                        Received::Content(content) => {
                            handle_content(manager, &content, &mut on_consignment).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Describe a content body variant for diagnostics, without dumping contents.
fn body_kind(content: &Content) -> String {
    match &content.body {
        ContentBody::NullMessage(_) => "null message".into(),
        ContentBody::DataMessage(_) => "data message (unhandled)".into(),
        ContentBody::SynchronizeMessage(sync) => {
            let field = match () {
                _ if sync.sent.is_some() => "sent",
                _ if sync.contacts.is_some() => "contacts",
                _ if sync.request.is_some() => "request",
                _ if !sync.read.is_empty() => "read",
                _ if sync.blocked.is_some() => "blocked",
                _ if sync.keys.is_some() => "keys",
                _ => "other",
            };
            let has_dm = sync
                .sent
                .as_ref()
                .is_some_and(|sent| sent.message.is_some());
            format!("sync message ({field}, data_message={has_dm})")
        }
        ContentBody::CallMessage(_) => "call message".into(),
        ContentBody::ReceiptMessage(_) => "receipt".into(),
        ContentBody::TypingMessage(_) => "typing indicator".into(),
        ContentBody::DecryptionErrorMessage(_) => "decryption error".into(),
        ContentBody::StoryMessage(_) => "story message".into(),
        ContentBody::PniSignatureMessage(_) => "pni signature message".into(),
        ContentBody::EditMessage(_) => "edit message".into(),
    }
}

/// Handle one decrypted incoming message.
async fn handle_content<F>(manager: &SignalManager, content: &Content, on_consignment: &mut F)
where
    F: FnMut(&[u8]) -> String,
{
    let sender = content.metadata.sender.raw_uuid();
    let data_messages: Vec<&DataMessage> = match &content.body {
        ContentBody::DataMessage(data_message) => vec![data_message],
        // A message we sent from another device (e.g. the phone, or this CLI
        // from another terminal) echoes back as a sync "sent" transcript —
        // this is how Note-to-Self consignments arrive.
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(Sent {
                    message: Some(data_message),
                    ..
                }),
            ..
        }) => vec![data_message],
        _ => vec![],
    };

    if data_messages.is_empty() {
        println!(
            "from {sender}: not an OpenCSV consignment ({})",
            body_kind(content)
        );
        return;
    }

    for data_message in data_messages {
        let mut handled = false;
        for pointer in &data_message.attachments {
            if !is_consignment_attachment(
                pointer.file_name.as_deref(),
                pointer.content_type.as_deref(),
                data_message.body.as_deref(),
            ) {
                continue;
            }
            handled = true;
            match manager.get_attachment(pointer).await {
                Ok(blob) => {
                    println!("consignment from {sender} ({} bytes)", blob.len());
                    let verdict = on_consignment(&blob);
                    println!("{verdict}");
                }
                Err(e) => println!("REJECTED could not download attachment: {e}"),
            }
        }
        if !handled {
            let preview: String = data_message
                .body
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect();
            println!(
                "from {sender}: not an OpenCSV consignment ({} attachment(s), body {preview:?})",
                data_message.attachments.len()
            );
        }
    }
}

/// Open the sqlite store at `<store_dir>/signal.db` (unencrypted).
async fn open_store(store_dir: &Path) -> Result<SqliteStore, Error> {
    std::fs::create_dir_all(store_dir).map_err(|source| Error::Io {
        path: store_dir.to_path_buf(),
        source,
    })?;
    let db = store_dir.join(STORE_FILE);
    SqliteStore::open_with_passphrase(&db.to_string_lossy(), None, OnNewIdentity::Trust)
        .await
        .map_err(|e| Error::Signal(format!("could not open store {}: {e}", db.display())))
}
