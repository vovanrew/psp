### psp
psp collects statistic about network

1. A daemon sniffs packets from particular interface. It
saves ip addresses of incoming packets and number of packets from each ip.

2. Time complexity for ip search is log(N).

3. Statistic is persistent through reboots.

4. The cli support commands:

  a. start (packets are being sniffed from now on)

  b. stop (packets are not sniffed)

  c. show [ip] count (printf number of packets received from ip address)

  d. select iface [iface] (select interface for sniffing)

  e. -- help (show usage information)

5. Daemon is started independently as well as through the cli.
