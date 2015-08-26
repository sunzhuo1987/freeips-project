![http://freeips-project.googlecode.com/svn/wiki/images/logo.png](http://freeips-project.googlecode.com/svn/wiki/images/logo.png)

FreeIPS is a multi-threaded IPS written from scratch and currently capable of:<br>

<ul><li>IP fragment reassembly<br>
</li><li>TCP session management<br>
<ul><li>Typical for "flow" support<br>
</li></ul></li><li>Inline support<br>
<ul><li>Uses IPDIVERT<br>
</li><li>Can drop connections<br>
</li></ul></li><li>Snort signature compatibility<br>
</li><li>Many logging features<br>
<ul><li>Packet dumping (HEX, pcap)<br>
</li><li>Syslog, logfiles<br>
</li></ul></li><li>HTTP control interface<br>
<ul><li>Authenticated<br>
</li><li>Binds to configurable address<br>
</li><li>Remote management possible<br>
</li></ul></li><li>Multithreaded<br>
<ul><li>1:1 threading, SMP optimized<br>
</li><li>Limited data copy's<br>
</li></ul></li><li>Highly configurable<br>
<ul><li>XML config file<br>
</li></ul></li><li>.....</li></ul>

Snort signature compatibility was included due to the fact that the availability of these signatures is high which makes it easier for Snort users to try out and maintain a FreeIPS.<br>
A large amount of the existing Snort signatures can be loaded but keep in mind that signatures with keywords not supported yet are discarded (optionally you can also load these but that's not recommended.<br>
<br>
Status: experimental, not stable, for testing only