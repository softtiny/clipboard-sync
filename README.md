## Clipboard sync

synchronize your clipboards across multiple devices

## Howto run

## run without config 

```
KEY="32323232323232323232323232323232"
clipboard-sync --key <(echo "$KEY")
```

```
cargo run --  --key <(echo "$KEY") --allowed-host "127.0.0.1:8000" --clipboard /tmp/b --verbose debug --bind-address 127.0.0.1:9000 --send-using-address 127.0.0.1:9001
```

check for more options 

```
clipboard-sync --help
```

## run with config 

```
clipboard-sync --config ~/.config/clipboard-sync.yaml
```

### example config

```yaml
bind_address: "0.0.0.0:8900"
# send_using_address and public_ip are per group as well
send_using_address: "0.0.0.0:8901"
public_ip: "1.1.1.1"

groups:
  specific_hosts:
    key: "32323232323232323232323232323232"
    allowed_hosts:
      - "192.168.0.153:8900"
      - "192.168.0.54:20034"
    clipboard: clipboard # can be clipboard, /path/to/file , /path/to/directory/
  local_network: 
    key: "32323232323232323232323232323232"
    # allowed_hosts default to local network multicas
  external:
    key: "32323232323232323232323232323232"
    public_ip: "2.2.2.2"
    send_using_address: "0.0.0.0:9000"
    allowed_hosts:
      - "3.3.3.3:80"
  local_network_file: 
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard # sync file
  local_network_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard/dir/ # sync dir
  receive_only_dir:
    key: "32323232323232323232323232323232"
    clipboard: /tmp/cliboard/dir/ # files will be created as /tmp/cliboard/dir/192.168.0.111
    allowed_hosts:
      - "192.168.0.111:0" # port 0 - receive only
      - "192.168.0.112:0"
```