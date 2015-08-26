Setting up inline mode is not that hard. Just make sure that your machine can already <br>
function as a gateway AND that it has IPFW configured. Add the following rule to divert<br> traffic to FreeIPS:<br>

<ul><li>ipfw add 410 divert 2222 ip4 from any to any</li></ul>

Now tell FreeIPS to get the traffic:<br>
<ul><li>/FreeIPS -c config/config.xml -I -P 2222</li></ul>

Your config.xml needs to be modified for your needs and keep in mind that you can also <br>
configure the inline mode and port in the config.xml file<br>
