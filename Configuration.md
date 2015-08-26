# Introduction #

FreeIPS can be configured using the config.xml file, or by using
the command-line flag. In general you want to use the config.xml
file and if necessary overwrite settings with additional flags.
This because the config.xml allows much more default settings to
be overwritten and therefore you're better able to tune the IPS for
your needs.

## Example config.xml ##

```

<?xml version="1.0"?>
<config>
  <general>
        <sigfile>./config/signatures/</sigfile>
        <sigstrict>1</sigstrict>
        <tcpstrict>1</tcpstrict>
        <pcapfilter>ip</pcapfilter>
        <pcapdevice>em0</pcapdevice>
        <inline>0</inline>
        <inlineport>2222</inlineport>

        <!-- how many packets to store in memory -->
        <ringbuffer>800000</ringbuffer>

        <security>
                <run_as_user enable="1">nobody</run_as_user>
                <chroot_dir  enable="0">/var/chroot</chroot_dir>
                <!-- If you chroot, make sure logdir is there -->
        </security>
  </general>

  <logging>
        <verbosity>1</verbosity>
        <syslog>0</syslog>
        <stdout>1</stdout>
        <showtraffic>0</showtraffic>

        <logfile enable="1" level="alert">
                <filename>./logdir/alert.log</filename>
        </logfile>

        <logfile enable="1" level="info">
                <filename>./logdir/info.log</filename>
        </logfile>

        <dump_packet enable="1">
                <output_dir>./logdir/</output_dir>
        </dump_packet>
  </logging>

  <control_thread>
        <http enable="1" port="3491" ip="127.0.0.1">
                <user>user</user>
                <pass>pass</pass>
        </http>
        <html_footer>support/html/footer.html</html_footer>
        <html_header>support/html/header.html</html_header>

        <timer>
                <print_stats>1</print_stats>
                <cleanup_tcp>3600</cleanup_tcp>
                <cleanup_ipfrags>10</cleanup_ipfrags>
                <cleanup_packetbuffer>3</cleanup_packetbuffer>
        </timer>
  </control_thread>
</config>

```

## Parameters explained ##

|**Parameter**|**Explanation**|
|:------------|:--------------|
|sigfile      |Location of the signature folder OR a single signature file. If you specify a folder then it will be read recursively (thus including subdirectories)|
|sigstrict    |If set to 1: Only signatures with fully supported by FreeIPS are loaded. If set to 0 then signatures with non-supported keywords are also loaded |
|tcpstrict    |If set to 1: Drop TCP packets not part of a known session. When running in inline mode, this means that existing connections may be dropped during startup of the IPS|
|pcapfilter   |Specify the PCAP filter here|
|pcapdevice   |Network interface to read from.|
|inline       |If set to 1: Inline mode is enabled and packets are read from DIVERT instead of the network interface|
|inlineport   |This is in fact the DIVERT port. It should match with your IPFW rules|
|ringbuffer   |With this setting you can specify the ringbuffer size. This is the memory buffer thats created during startup of FreeIPS. In the buffer packets are being stored by the sniffer thread. Keep the buffer big and use this rule: the faster the network, the bigger the need for a large buffer. If there are larege amounts of traffic then at some points the analyzer thread cannot keep up with the sniffer. At that point the buffer should be able to store the packets until the analyzer catches up. |


