# Suricata in Docker

The open-source Intrusion Detection System, in Docker, built from source with **suricata-update**, **Hyperscan**, **GeoIP** and **Lua** support.

## Usage

To build a fresh Suricata Docker Image, from the root directory of this repo execute:

```bash
docker build -f docker/Dockerfile -t suricata:latest .
```

Then to run a Suricata container, just execute:

```bash
docker run -d \
    --name suricata \
    --privileged \
    --network host \
    suricata:latest \
        -i <INTERFACE>
  ```

Additional Suricata arguments can be apended to the end of the above command and are documented here: http://suricata.readthedocs.io/en/latest/command-line-options.html
