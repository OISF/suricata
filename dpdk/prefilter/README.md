# DPDK Prefilter

DPDK Prefilter is an application running in front of Suricata with the main purpose of receiving packets of the NICs 
and distributing those packets among Suricata workers. Additionally, DPDK Prefilter can provide bypass functionality 
for Suricata. 

## How to set it up

### Compilation

1. clone the DPDK Prefilter branch
2. [install Suricata dependencies](https://suricata.readthedocs.io/en/latest/install.html#ubuntu-debian)
3. from within suricata directory run: 
   1. `./scripts/bundle.sh` - clones additional dependencies (libhtp and suricata-update) to `./suricata` directory
   2. `./autogen.sh`
   3. `echo "export PATH=/home/\$USER/.cargo/bin:\$PATH" >> ~/.bashrc` (or configure cargo your way)
   4. configure script (`./configure`) additionally with these flags: `--enable-dpdk --enable-dpdk-apps`
   5. `make -j10`
   6. `make install && make install-conf` - at this point you have compiled and installed standalone Suricata 
   7. `make install-headers && make install-library` - Suricata library is used by DPDK Prefilter
   8. `echo "<PATH_TO_SURICATA_INSTALL_FOLDER>/usr/lib" | sudo tee /etc/ld.so.conf.d/dpdk_prefilter.conf`
   9. `sudo ldconfig` - at this point you have installed Suricata library
   10. `make dpdk-apps` - now your DPDK Prefilter is compiled

### Running

1. Make sure you have DPDK-compatible drivers bound to your NIC and hugepages allocated.
2. Run DPDK Prefilter
3. Run Suricata

#### Running DPDK Prefilter
If you have successfully compiled DPDK Prefilter then it should be located in the `suricata/dpdk/prefilter/build` 
folder. DPDK Prefilter run arguments follow the DPDK-way of passing arguments to applications, meaning
DPDK EAL arguments are the first ones and application arguments are divided by `--`.

Running DPDK Prefilter can look like (from within `suricata/` folder):\
`sudo ./dpdk/prefilter/build/prefilter --proc-type=primary -l 18 -- -c ./dpdk/prefilter/conf.yaml -l info`

#### Running Suricata (with DPDK Prefilter)
Suricata can be started only if DPDK Prefilter **is already running**. If this condition is met then Suricata can be 
started as e.g.:\
`sudo <SURI_INSTALL_PREFIX>/bin/suricata --dpdk -c suricata-dpdk-prefilter.yaml -S /dev/null`

Parameter `-c` denotes path to the configuration file and parameter `-S` allows specifying path to the rule file 
(in this test case waiting for rules to load is unwanted).

File `suricata-dpdk-prefilter.yaml` should contain Suricata configuration along with DPDK section to attach to DPDK 
Prefilter. The DPDK section can look like:

```yaml
dpdk:
  eal-params:
    proc-type: secondary
    # Lcores are configured in cpu-affinity section

  interfaces:
    - interface: rx_myring_$QQQ # PCIe address of the NIC port
      # DPDK prefilter - DPDK application placed in front of Suricata to handle communication with the NIC
      # Prefilter communicates with Suricata via rings. Suricata accepts ring name patterns as the name of the 
      # individual rings. 
      # If prefilter is set on at least one interface, it is required all interfaces uses some prefilter.
      operation-mode: ring
      threads: 4 # or number of threads - auto takes all lcores, no thread entry takes all cores
      # IPS mode for Suricata works in 3 modes - none, tap, ips
      # - none: disables IPS functionality (does not further forward packets)
      # - tap: forwards all packets and generates alerts (omits DROP action)
      # - ips: the same as tap mode but it also drops packets that are flagged by rules to be dropped
      copy-mode: none
      copy-iface: none # tx_myring_$QQQ or PCIe address of the second interface
```
