use flume::{Receiver, Sender};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{sleep, Duration};

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use crate::clipboards::{
    create_targets_for_cut_files, create_text_targets, Clipboard, ClipboardType,
};
use crate::config::{FullConfig, Groups};
use crate::defaults::*;
use crate::encryption::*;
use crate::errors::*;
use crate::filesystem::*;
use crate::fragmenter::{GroupsEncryptor, IdentityEncryptor};
use crate::identity::{retrieve_identity, Identity};
use crate::message::*;
use crate::multicast::Multicast;
use crate::notify::{create_watch_paths, watch_changed_paths};
use crate::protocols::{receive_data, send_data, Protocol, SocketPool};
use crate::socket::*;
use crate::validation::validate;

pub type SocketAddrPool = HashMap<IpAddr, u16>;
pub type MessageReceived = (String, String, SocketAddr);

pub async fn receive_clipboard(
    pool: Arc<SocketPool>,
    mut clipboard: Clipboard,
    channel: Sender<MessageReceived>,
    local_address: SocketAddr,
    running: Arc<AtomicBool>,
    config: FullConfig,
    protocol: Protocol,
    status_channel: Sender<(u64, u64)>,
    receive_once: bool,
) -> Result<(String, u64), CliError>
{
    let local_socket = match pool.obtain_server_socket(local_address, &protocol).await {
        Ok(s) => s,
        Err(e) => {
            running.store(false, Ordering::Relaxed);
            return Err(CliError::from(e));
        }
    };
    let mut multicast = Multicast::default();
    let mut count = 0;
    let groups = config.groups;
    let encryptor = GroupsEncryptor::new(groups.clone());

    info!("Listen on {} protocol {}", local_address, protocol);

    if let Some(s) = local_socket.socket() {
        multicast
            .join_groups(&s, &groups, &s.local_addr()?.ip())
            .await;
    }

    let timeout = |_: Duration| !running.load(Ordering::Relaxed);
    let mut last_error = None;

    while running.load(Ordering::Relaxed) {
        let (raw_data, addr) = match receive_data(
            local_socket.clone(),
            &encryptor,
            &protocol,
            config.max_receive_buffer,
            timeout,
        )
        .await
        {
            Ok((d, _)) if d.is_empty() => continue,
            Ok(v) => v,
            Err(ConnectionError::InvalidKey(e)) | Err(ConnectionError::InvalidProtocol(e)) => {
                error!("Unable to continue. {}", e);
                running.store(false, Ordering::Relaxed);
                return Err(CliError::ArgumentError(e));
            }
            Err(ConnectionError::IoError(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                error!("Error receiving: {}", e);
                continue;
            }
        };

        count += 1;

        debug!("Packet received from {} length {}", addr, raw_data.len());

        // in ipv6 sockets ipv4 mapped address should be use as ipv4 address

        let result = handle_receive(
            &mut clipboard,
            raw_data,
            &Identity::from_mapped(&addr),
            &groups,
            config.max_file_size,
            config.app_dir.as_deref(),
        );

        match result {
            Ok((hash, group_name)) => {
                if let Err(msg) = channel.try_send((group_name, hash, addr)) {
                    warn!("Unable to update current hash {}", msg);
                }
            }

            Err(err) => {
                error!("{}", err);
                last_error = Some(CliError::ClipboardError(err));
            }
        };
        if status_channel.try_send((0, count)).is_err() {
            // debug!("Unable to send status count {}", e);
        }

        if receive_once {
            running.store(false, Ordering::Relaxed);
            if let Some(err) = last_error {
                return Err(err);
            }
            info!("Waiting for {} seconds", config.receive_once_wait);
            sleep(Duration::from_secs(config.receive_once_wait)).await;
            break;
        }
    }
    Ok((format!("{} received", protocol), count))
}

pub async fn send_clipboard(
    pool: Arc<SocketPool>,
    mut clipboard: Clipboard,
    channel: Receiver<MessageReceived>,
    running: Arc<AtomicBool>,
    config: FullConfig,
    status_channel: Sender<(u64, u64)>,
    send_once: bool,
) -> Result<(String, u64), CliError>
{
    let mut hash_cache: HashMap<String, String> = HashMap::new();
    let mut heartbeat_cache: HashMap<String, Instant> = HashMap::new();
    let mut count = 0;
    let groups = config.groups;
    let mut socket_addr_pool = SocketAddrPool::new();

    info!("Listen for clipboard changes");

    let mut last_error = None;

    let mut paths_to_watch: HashMap<PathBuf, Vec<&str>> = HashMap::new();

    for (_, group) in groups
        .iter()
        .filter(|(_, g)| g.clipboard != DEFAULT_CLIPBOARD)
    {
        let key = PathBuf::from(&group.clipboard);
        paths_to_watch
            .entry(key)
            .and_modify(|v| v.push(group.name.as_ref()))
            .or_insert_with(|| vec![group.name.as_ref()]);
    }
    let mut watcher = create_watch_paths(&paths_to_watch);

    let timeout = {
        let run_state = running.clone();
        move |_: Duration| !run_state.load(Ordering::Relaxed)
    };

    let hash_update = |hash_cache: &mut HashMap<String, String>, pool: &mut SocketAddrPool| {
        while let Ok((group_name, rhash, remote_socket)) = channel.try_recv() {
            let current_hash = match hash_cache.get(&group_name) {
                Some(val) => val.clone(),
                None => "".to_owned(),
            };
            pool.insert(remote_socket.ip(), remote_socket.port());
            if !rhash.is_empty() && current_hash != rhash {
                hash_cache.insert(group_name.clone(), rhash.clone());
                debug!(
                    "Client updated current hash {} to {} for group {}",
                    current_hash, rhash, group_name
                );
            }
        }
    };

    while running.load(Ordering::Relaxed) {
        if let Ok((ref mut watcher, ref receiver)) = watcher {
            for (_, group_names) in watch_changed_paths(watcher, receiver, &paths_to_watch) {
                for group_name in group_names {
                    hash_cache.insert(group_name.to_owned().to_string(), "".to_owned());
                }
            }
        }

        hash_update(&mut hash_cache, &mut socket_addr_pool);

        for (_, group) in &groups {
            if group.heartbeat > 0 {
                send_heartbeat(
                    &pool,
                    &socket_addr_pool,
                    group,
                    &mut heartbeat_cache,
                    timeout.clone(),
                )
                .await;
            }

            let (hash, message_type, bytes) = match clipboard_group_to_bytes(
                &mut clipboard,
                group,
                hash_cache.get(&group.name),
                config.max_file_size,
            ) {
                Some((hash, message_type, bytes)) if !bytes.is_empty() => {
                    (hash, message_type, bytes)
                }
                _ => {
                    continue;
                }
            };
            hash_update(&mut hash_cache, &mut socket_addr_pool);

            let entry_value = match hash_cache.get(&group.name) {
                Some(val) => val.to_owned(),
                None => {
                    if config.send_clipboard_on_startup {
                        String::new()
                    } else {
                        hash_cache.insert(group.name.clone(), hash.clone());
                        hash.clone()
                    }
                }
            };

            if entry_value == hash {
                continue;
            }

            hash_cache.insert(group.name.clone(), hash.clone());

            debug!("Clipboard changed from {} to {}", entry_value, &hash);

            let data = match compress(&bytes) {
                Ok(d) => d,
                Err(err) => {
                    error!("Failed to compress data for {} {}", &group.name, err);
                    continue;
                }
            };

            match send_clipboard_to_group(
                &pool,
                &socket_addr_pool,
                &data,
                &message_type,
                group,
                timeout.clone(),
            )
            .await
            {
                Ok(sent) if sent > 0 => {
                    debug!("Sent bytes {}", sent);
                    count += 1;
                }
                Ok(_) => (),
                Err(err) => {
                    error!("Error sending: {}", err);
                    last_error = Some(err);
                }
            };

            if status_channel.try_send((count, 0)).is_err() {
                // debug!("Unable to send status count {}", e);
            }
        }
        if send_once {
            running.store(false, Ordering::Relaxed);
            if let Some(err) = last_error {
                return Err(CliError::ClipboardError(err));
            }
            break;
        }

        sleep(Duration::from_millis(500)).await;
    }
    Ok(("sent".to_string(), count))
}

pub async fn send_clipboard_contents(
    pool: &SocketPool,
    addr_pool: &SocketAddrPool,
    bytes: &[u8],
    group: &Group,
    message_type: MessageType,
) -> Result<usize, String>
{
    let data = match compress(bytes) {
        Ok(d) => d,
        Err(err) => {
            return Err(format!(
                "Failed to compress data for {} {}",
                &group.name, err
            ));
        }
    };
    let timeout = |d: Duration| d > Duration::from_millis(DATA_TIMEOUT + DATA_TIMEOUT);

    match send_clipboard_to_group(pool, addr_pool, &data, &message_type, group, timeout).await {
        Ok(sent) => {
            debug!("Sent bytes {}", sent);
            Ok(sent)
        }
        Err(err) => {
            error!("{}", err);
            Err(err.to_string())
        }
    }
}

async fn send_heartbeat(
    pool: &SocketPool,
    addr_pool: &SocketAddrPool,
    group: &Group,
    heartbeat_cache: &mut HashMap<String, Instant>,
    timeout: impl Fn(Duration) -> bool + Send + Sync + Clone + 'static,
)
{
    let (send, last) = if let Some(last) = heartbeat_cache.get(&group.name) {
        (last.elapsed().as_secs() >= group.heartbeat, *last)
    } else {
        (true, Instant::now())
    };
    if send {
        let data = last.elapsed().as_secs().to_be_bytes();
        heartbeat_cache.insert(group.name.clone(), Instant::now());
        match send_clipboard_to_group(
            pool,
            addr_pool,
            &data,
            &MessageType::Heartbeat,
            group,
            timeout,
        )
        .await
        {
            Ok(sent) => debug!("Sent heartbeat bytes {}", sent),
            Err(err) => error!("Error heartbeat: {}", err),
        };
    }
}

fn clipboard_group_to_bytes(
    clipboard: &mut Clipboard,
    group: &Group,
    existing_hash: Option<&String>,
    max_file_size: usize,
) -> Option<(String, MessageType, Vec<u8>)>
{
    if group.clipboard == CLIPBOARD_NAME {
        clipboard_to_bytes(clipboard, existing_hash, max_file_size)
    } else if Path::new(&group.clipboard).exists() {
        if let Some(h) = existing_hash {
            if !h.is_empty() {
                return None;
            }
        }
        if Path::new(&group.clipboard).is_dir() {
            match dir_to_bytes(&group.clipboard, max_file_size) {
                Ok(bytes) => return Some((hash(&bytes), MessageType::Directory, bytes)),
                Err(_) => return None,
            };
        }
        match read_file(&group.clipboard, max_file_size) {
            Ok((bytes, full)) if full => Some((hash(&bytes), MessageType::File, bytes)),
            Ok(_) => {
                warn!(
                    "Unable to read file {} file is larger than {}",
                    &group.clipboard, max_file_size
                );
                None
            }
            Err(_) => None,
        }
    } else {
        None
    }
}

fn clipboard_to_bytes(
    clipboard: &mut Clipboard,
    existing_hash: Option<&String>,
    max_file_size: usize,
) -> Option<(String, MessageType, Vec<u8>)>
{
    let files = clipboard.get_target_contents(ClipboardType::Files);
    match files {
        Ok(data) if !data.is_empty() => {
            let hash = hash(&data);
            if let Some(h) = existing_hash {
                if h == &hash {
                    return None;
                }
            }
            let clipboard_contents = String::from_utf8(data).ok()?;
            // debug!("Send file clipboard {}", clipboard_contents);
            let files: Vec<String> = clipboard_contents
                .lines()
                .filter_map(|p| {
                    let no_prefix = p.strip_prefix("file://").unwrap_or(p);
                    let add_prefix = if p != no_prefix {
                        |s| format!("file://{}", s)
                    } else {
                        |s| s
                    };
                    decode_path(no_prefix).ok().map(add_prefix)
                })
                .collect();
            Some((
                hash,
                MessageType::Files,
                files_to_bytes(files.iter().map(AsRef::as_ref).collect(), max_file_size).ok()?,
            ))
        }
        _ => match clipboard.get_target_contents(ClipboardType::Text) {
            Ok(contents) => {
                let hash = hash(&contents);
                if let Some(h) = existing_hash {
                    if h == &hash {
                        return None;
                    }
                }
                Some((hash, MessageType::Text, contents))
            }
            _ => {
                warn!("Failed to retrieve contents");
                None
            }
        },
    }
}

fn handle_receive(
    clipboard: &mut Clipboard,
    raw_data: Vec<u8>,
    identity: &Identity,
    groups: &Groups,
    max_file_size: usize,
    app_dir: Option<&str>,
) -> Result<(String, String), ClipboardError>
{
    let (mut message, group) = validate(raw_data, groups, identity)?;
    let bytes = decrypt(&mut message, identity, group)?;
    let data = match message.message_type {
        MessageType::Heartbeat => bytes,
        _ => uncompress(bytes)?,
    };
    write_to(
        clipboard,
        group,
        data,
        &message.message_type,
        identity,
        max_file_size,
        app_dir,
    )
}

fn write_to(
    clipboard: &mut Clipboard,
    group: &Group,
    data: Vec<u8>,
    message_type: &MessageType,
    identity: &Identity,
    max_file_size: usize,
    app_dir: Option<&str>,
) -> Result<(String, String), ClipboardError>
{
    if message_type == &MessageType::Heartbeat {
        return Ok(("".to_owned(), group.name.clone()));
    }
    if group.clipboard == CLIPBOARD_NAME {
        match message_type {
            MessageType::Files | MessageType::File => {
                let config_dir = app_dir
                    .map(PathBuf::from)
                    .or_else(|| dirs::config_dir().map(|p| p.join(PACKAGE_NAME)));
                let config_path = config_dir
                    .map(|p| p.join("data"))
                    .map(|p| p.join(identity.to_string()))
                    .map(|path| path.to_string_lossy().to_string())
                    .ok_or_else(|| {
                        ClipboardError::Invalid("Unable to retrieve configuration path".to_owned())
                    })?;
                let files_created =
                    bytes_to_dir(&config_path, data, &identity.to_string(), max_file_size)?;
                let (clipboard_list, main_content) = create_targets_for_cut_files(files_created);
                let clipboards: HashMap<ClipboardType, &[u8]> = clipboard_list
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_bytes()))
                    .collect();
                let hash = hash(main_content.as_bytes());
                clipboard
                    .set_multiple_targets(clipboards)
                    .map_err(|err| ClipboardError::Access((*err).to_string()))?;
                return Ok((hash, group.name.clone()));
            }
            _ => {
                let hash = hash(&data);
                clipboard
                    .set_multiple_targets(create_text_targets(&data))
                    .map_err(|err| ClipboardError::Access((*err).to_string()))?;
                return Ok((hash, group.name.clone()));
            }
        };
    } else if group.clipboard.ends_with('/') || Path::new(&group.clipboard).is_dir() {
        let hash = hash(&data);
        bytes_to_dir(&group.clipboard, data, &identity.to_string(), max_file_size)?;
        return Ok((hash, group.name.clone()));
    }
    let hash = hash(&data);
    write_file(&group.clipboard, data, 0o600)?;
    Ok((hash, group.name.clone()))
}

async fn send_clipboard_to_group(
    pool: &SocketPool,
    addr_pool: &SocketAddrPool,
    buffer: &[u8],
    message_type: &MessageType,
    group: &Group,
    callback: impl Fn(Duration) -> bool + Send + Sync + Clone + 'static,
) -> Result<usize, ClipboardError>
{
    let mut sent = 0;
    for remote_host_str in &group.allowed_hosts {
        let use_latest = remote_host_str.ends_with(":latest");
        let remote_host = if use_latest {
            remote_host_str.replace(":latest", "")
        } else {
            remote_host_str.to_owned()
        };
        let addr = match to_socket_address(&remote_host) {
            Ok(a) => {
                if use_latest {
                    let port: u16 = addr_pool.get(&a.ip()).copied().unwrap_or_else(|| a.port());
                    SocketAddr::new(a.ip(), port)
                } else {
                    a
                }
            }
            Err(e) => {
                warn!("{}", e);
                continue;
            }
        };

        if addr.port() == 0 {
            debug!("Not sending to host {}", &remote_host);
            continue;
        }

        let remote_ip = addr.ip();
        let identity = retrieve_identity(&addr, group).await?;

        let local_socket = pool
            .obtain_client_socket(
                &group.send_using_address,
                &addr,
                &group.protocol,
                group.heartbeat > 0_u64,
            )
            .await?;

        let bytes = encrypt_serialize_to_bytes(buffer, &identity, group, message_type)?;

        debug!(
            "Sending to {}:{} using {} length {}",
            remote_ip,
            addr.port(),
            identity,
            bytes.len(),
        );

        let encryptor = IdentityEncryptor::new(group.clone(), identity);

        let host = remote_host
            .strip_suffix(&format!(":{}", addr.port()))
            .unwrap_or(&remote_host);

        sent += send_data(
            local_socket,
            encryptor,
            &group.protocol,
            Destination::new(host.to_owned(), addr),
            bytes,
            callback.clone(),
        )
        .await?;
    }
    Ok(sent)
}

#[cfg(test)]
mod processtest
{
    use super::*;
    use crate::message::Group;
    use crate::wait;
    use indexmap::{indexmap, indexset};
    use tokio::task::JoinHandle;
    use tokio::try_join;

    #[test]
    fn test_handle_clipboard_change()
    {
        let pool = SocketPool::default();
        let addr_pool = SocketAddrPool::new();
        let timeout = |d: Duration| d > Duration::from_millis(2000);
        let result = wait!(send_clipboard_to_group(
            &pool,
            &addr_pool,
            b"test",
            &MessageType::Text,
            &Group::from_name("me"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);

        let result = wait!(send_clipboard_to_group(
            &pool,
            &addr_pool,
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:0", "127.0.0.1:8093"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 82);

        let result = wait!(send_clipboard_to_group(
            &pool,
            &addr_pool,
            b"test",
            &MessageType::Text,
            &Group::from_addr("me", "127.0.0.1:8801", "127.0.0.1:0"),
            timeout,
        ));
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_send_clipboard()
    {
        // env_logger::from_env(env_logger::Env::default().default_filter_or("debug")).init();
        let clipboards = Clipboard::new().unwrap();
        let clipboardr = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8391", "127.0.0.1:8392");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, rx) = flume::bounded(MAX_CHANNEL);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8392".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            indexset! {local_address},
            indexmap! { group.name.clone() => group.clone() },
            100,
            100,
            20,
            true,
            None,
            None,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);
        let pool = Arc::new(SocketPool::default());

        let r = tokio::spawn(receive_clipboard(
            pool.clone(),
            clipboards,
            tx,
            local_address,
            Arc::clone(&running),
            config.clone(),
            protocol,
            stat_sender.clone(),
            false,
        ));
        let s = tokio::spawn(send_clipboard(
            pool.clone(),
            clipboardr,
            rx,
            Arc::clone(&running),
            config,
            stat_sender.clone(),
            false,
        ));
        let t: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let mut clipboard = Clipboard::new().unwrap();
            write_to(
                &mut clipboard,
                &group,
                "test1".as_bytes().to_vec(),
                &MessageType::Text,
                &"0.0.0.0".parse::<IpAddr>().unwrap().into(),
                100,
                None,
            )
            .unwrap();
            sleep(Duration::from_millis(1100)).await;
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(100)).await;
            Ok(())
        });
        match try_join!(r, s, t) {
            Ok(result) => {
                assert_eq!(result.0.unwrap().1, 1);
                assert_eq!(result.1.unwrap().1, 1);
            }
            Err(_) => panic!("failed to join"),
        };
    }

    #[tokio::test]
    async fn test_receive_clipboard()
    {
        let clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_addr("test1", "127.0.0.1:8393", "127.0.0.1:8394");
        group.clipboard = "/tmp/twtest1".to_owned();
        let (tx, _rx) = flume::bounded(MAX_CHANNEL);
        let (stat_sender, _) = flume::bounded(MAX_CHANNEL);
        let running = Arc::new(AtomicBool::new(true));
        let local_address: SocketAddr = "127.0.0.1:8394".parse().unwrap();
        let config = FullConfig::from_protocol_groups(
            Protocol::Basic,
            indexset! {local_address},
            indexmap! { group.name.clone() => group.clone() },
            100,
            100,
            20,
            false,
            None,
            None,
        );
        let protocol = Protocol::Basic;
        let srunning = Arc::clone(&running);
        let pool = Arc::new(SocketPool::default());
        let addr_pool = SocketAddrPool::new();

        let r = tokio::spawn(receive_clipboard(
            pool.clone(),
            clipboard,
            tx,
            local_address,
            running,
            config,
            protocol,
            stat_sender,
            false,
        ));
        let s: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let sent =
                send_clipboard_contents(&pool, &addr_pool, b"test1", &group, MessageType::Text)
                    .await;
            assert_eq!(94, sent.unwrap());
            // let server handle it
            sleep(Duration::from_millis(4000)).await;
            srunning.store(false, Ordering::Relaxed);
            sleep(Duration::from_millis(1000)).await;
            Ok(())
        });
        match try_join!(r, s) {
            Ok(result) => assert_eq!(result.0.unwrap().1, 1),
            Err(_) => panic!("failed to join"),
        };
    }

    #[test]
    fn test_clipboard_group_to_bytes()
    {
        let mut clipboard = Clipboard::new().unwrap();
        let mut group = Group::from_name("test1");

        group.clipboard = "tests/test-dir/a".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(
            res,
            Some((
                "4644417185603328019".to_owned(),
                MessageType::File,
                vec![97]
            ))
        );

        group.clipboard = CLIPBOARD_NAME.to_owned();

        clipboard
            .set_target_contents(ClipboardType::Text, b"test1")
            .unwrap();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(
            res,
            Some((
                "17623087596200270265".to_owned(),
                MessageType::Text,
                vec![116, 101, 115, 116, 49]
            ))
        );

        group.clipboard = "tests/test-dir/".to_owned();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(
            res,
            Some((
                "12908774274447230140".to_owned(),
                MessageType::Directory,
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97,
                    1, 0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98
                ]
            ))
        );

        group.clipboard = "tests/test-dir".to_owned();

        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(
            res,
            Some((
                "12908774274447230140".to_owned(),
                MessageType::Directory,
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 97, 1, 0, 0, 0, 0, 0, 0, 0, 97,
                    1, 0, 0, 0, 0, 0, 0, 0, 98, 1, 0, 0, 0, 0, 0, 0, 0, 98
                ]
            ))
        );

        group.clipboard = "tests/non-existing".to_owned();
        let res = clipboard_group_to_bytes(&mut clipboard, &group, None, 100);
        assert_eq!(res, None);
    }

    #[test]
    fn test_path_buf_comparison()
    {
        assert!(PathBuf::from("/tmp/") == PathBuf::from("/tmp"));
        assert!(Path::new("/tmp/").is_dir());
    }
}
