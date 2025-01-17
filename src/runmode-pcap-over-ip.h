#ifndef SURICATA_RUNMODE_PCAP_OVER_IP_H
#define SURICATA_RUNMODE_PCAP_OVER_IP_H

int RunModePcapOverIPSingle(void);
int RunModePcapOverIPAutoFp(void);
void RunModePcapOverIPRegister(void);
const char *RunModePcapOverIPGetDefaultMode(void);

#endif /* SURICATA_RUNMODE_PCAP_OVER_IP_H */
