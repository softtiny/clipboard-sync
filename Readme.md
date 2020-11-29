## Clipboard sync

synchronize your clipboards across multiple devices

## run without config 

```
clipboard-sync --key "32323232323232323232323232323232"
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
send_using_address: "0.0.0.0:8901"
public_ip: "1.1.1.1"

groups:
  specific_hosts:
    key: "32323232323232323232323232323232"
    allowed_hosts:
      - "192.168.0.153:8900"
      - "192.168.0.54:20034"
  local_network: 
    key: "32323232323232323232323232323232"
    # allowed_hosts default to local network multicast
  external:
    key: "32323232323232323232323232323232"
    public_ip: "2.2.2.2"
    send_using_address: "0.0.0.0:9000"
    allowed_hosts:
      - "3.3.3.3:80"
```

