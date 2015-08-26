# Introduction #


## Compiling FreeIPS ##

Before getting started, you'll need the following installed

  * FreeBSD 6.`*` or higher
  * Libxml2    (/usr/ports/textproc/libxml2)
  * libpcre    (/usr/ports/devel/pcre)
  * subversion (/usr/ports/devel/subversion)

Fetch the code:<br>
<ul><li>svn checkout <a href='http://freeips-project.googlecode.com/svn/trunk/'>http://freeips-project.googlecode.com/svn/trunk/</a> freeips-project-read-only</li></ul>

Build the IPS:<br>
<ul><li>cd freeips-project-read-only<br>
</li><li>make</li></ul>

Running the IPS:<br>
<ul><li>./FreeIPS -i "interface" -S "path to signatures>"<br>
</li><li>E.g: ../FreeIPS -i xl0 -S config/signatures/<br>
Alternatively, edit "config/config.xml" and set the interface, signature path and<br>
anything else you want to enable, disable. Then run the IDP with the comment:<br>
</li></ul><ul><li>../FreeIPS -c config/config.xml</li></ul>

<h3>Ok and then..</h3>

<b>Tip 1</b><br>
You can keep your code in sync using the command "svn update" in the freeips-project-read-only<br>
<br>
directory.<br>
<br>
<b>Tip 2</b><br>
You'll notice that there are no signatures with the default install. You can get these<br>
from <a href='http://www.snort.com'>http://www.snort.com</a> or <a href='http://www.emergingthreats.net/'>http://www.emergingthreats.net/</a>

<ul><li>fetch <a href='http://www.emergingthreats.net/rules/emerging.rules.tar.gz'>http://www.emergingthreats.net/rules/emerging.rules.tar.gz</a>
</li><li>tar -zxvf emerging.rules.tar.gz<br>
</li><li>./FreeIPS -i xl0 -S rules/