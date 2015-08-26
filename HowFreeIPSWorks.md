# Summary of how it works #

FreeIPS is multithreaded and each thread has its task and this is shown in the picture below.

![http://freeips-project.googlecode.com/svn/wiki/images/freeips_how_it_works.jpg](http://freeips-project.googlecode.com/svn/wiki/images/freeips_how_it_works.jpg)

A sniffer thread listens on an interface or reads data from a file.
The packets read this way are pushed into into a ringbuffer in
memory.  In paralel, the analyzer thread reads the packets from the
ringbuffer and does the signature matching.

While the IPS is operational, another thead called "control thread",
makes sure that time based events are triggered. A typical time based
event is the cleaning expired IP fragment queue which helps to
control memory consumption. Another one is printing statistics. In
addition to these event, the control thread is responsible for handling
messaging which means it will print alerts to screen, file or syslog.

The control thread can also accept HTTP requests in order to provide
you some remote insight in statistics and log files. Via HTTP you can also
force the IPS to reload signatures. The idea is that in the future the HTTP
interface can be used for pushing configs and even cooler: communication
between multiple FreeIPS's.  For example to share blacklists.