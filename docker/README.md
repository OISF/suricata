# Suricata (4.0.5) in Docker

The open-source Intrusion Detection System, in Docker, built from source with **suricata-update**, **Hyperscan**, **GeoIP** and **Lua** support.

## Usage

```bash
docker build suricata:latest .
```

```bash
docker run -d \
    --name suricata \
    --privileged \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    suricata:latest \
        -i <INTERFACE>
  ```

Additional Suricata arguments can be apended to the end of the above command and are documented here: http://suricata.readthedocs.io/en/latest/command-line-options.html
