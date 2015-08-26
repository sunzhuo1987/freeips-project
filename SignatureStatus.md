# Introduction #

It was chosen to give the FreeIPS support for Snort signatures due to the large support <br>
there is available today for this format.  We do not need to re-invent the wheel and <br>
anyone familiar with Snort can also work with the FreeIPS.<br>

In fact, just download FreeIPS, then download some Snort signatures and your good to go.<br>
<br>
<h1>Links</h1>

Snort signatures are described in the snort manual<br>
<a href='http://www.snort.org/docs/'>http://www.snort.org/docs/</a>

Free signatures<br>
<a href='http://www.emergingthreats.net/'>http://www.emergingthreats.net/</a>

<h1>Signature support status</h1>

The table below gives you an indication of how much we actually are compatible with <br>
the Snort signatures.  Note that eventough the signature keywords are supported, the<br>
usage and processing in the engine is likely to be different.  However, you can expect<br>
that in the end the attack detection is the same...<br>
<br>
It should be noted that it's not the goal to support 100% of all signatures. The goal<br> is to be as much compatible as possible without implementing sub-optimal code<br>

Note: The below lists are based on the 2.8.4 snort user manual<br>
<br>
<h2>Payload processing</h2>

These are payload specific<br>
<br>
<table><thead><th><b>Keyword</b></th><th><b>Status</b></th><th><b>Comment</b></th></thead><tbody>
<tr><td>content       </td><td><font color='green'>Done</font></td><td>              </td></tr>
<tr><td>nocase        </td><td><font color='green'>Done</font></td><td>Content modifier</td></tr>
<tr><td>rawbytes      </td><td><font color='red'>No</font></td><td>Content modifier</td></tr>
<tr><td>depth         </td><td><font color='green'>Done</font></td><td>Content modifier</td></tr>
<tr><td>offset        </td><td><font color='green'>Done</font></td><td>Content modifier</td></tr>
<tr><td>distance      </td><td><font color='green'>Done</font></td><td>Content modifier</td></tr>
<tr><td>within        </td><td><font color='green'>Done</font></td><td>Content modifier</td></tr>
<tr><td>http_client_body</td><td><font color='red'>No</font></td><td>Planned in HTTP processing</td></tr>
<tr><td>http_cookie   </td><td><font color='red'>No</font></td><td>Never used?   </td></tr>
<tr><td>http_header   </td><td><font color='red'>No</font></td><td>Never used?   </td></tr>
<tr><td>http_method   </td><td><font color='red'>No</font></td><td>Never used?   </td></tr>
<tr><td>http_uri      </td><td><font color='red'>No</font></td><td>Never used?   </td></tr>
<tr><td>fast_pattern  </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>uricontent    </td><td><font color='Green'>Yes</font></td><td>              </td></tr>
<tr><td>urilen        </td><td><font color='Orange'>Partially</font></td><td>Work in progress</td></tr>
<tr><td>isdataat      </td><td><font color='green'>yes</font></td><td>              </td></tr>
<tr><td>pcre          </td><td><font color='green'>yes</font></td><td>Snort modifiers need some work</td></tr>
<tr><td>byte_test     </td><td><font color='Orange'>Partially</font></td><td>              </td></tr>
<tr><td>byte_jump     </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>ftpbounce     </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>asn1          </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>cvs           </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>dce_iface     </td><td><font color='red'>No</font></td><td>very specific </td></tr>
<tr><td>dce_opnum     </td><td><font color='red'>No</font></td><td>Very specific </td></tr>
<tr><td>dce_stub_data </td><td><font color='red'>No</font></td><td>Very specific </td></tr></tbody></table>


<h2>Non-payload processing</h2>


These are related to traffic analysis<br>
<br>
<table><thead><th><b>Keyword</b></th><th><b>Status</b></th><th><b>Comment</b></th></thead><tbody>
<tr><td>fragoffset    </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>ttl           </td><td><font color='green'>Yes</font></td><td>              </td></tr>
<tr><td>tos           </td><td><font color='green'>Yes</font></td><td>              </td></tr>
<tr><td>id            </td><td><font color='green'>Yes</font></td><td>              </td></tr>
<tr><td>ipopts        </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>fragbits      </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>dsize         </td><td><font color='green'>Yes</font></td><td>              </td></tr>
<tr><td>flags         </td><td><font color='Orange'>Yes</font></td><td>Needs a review</td></tr>
<tr><td>flow          </td><td><font color='Orange'>Yes</font></td><td>Supported are: to_server,to_client,established.</td></tr>
<tr><td>flowbits      </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>seq           </td><td><font color='Green'>Yes</font></td><td>              </td></tr>
<tr><td>ack           </td><td><font color='Green'>Yes</font></td><td>              </td></tr>
<tr><td>window        </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>itype         </td><td><font color='Green'>Yes</font></td><td>              </td></tr>
<tr><td>icode         </td><td><font color='Green'>Yes</font></td><td>              </td></tr>
<tr><td>icmp_id       </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>icmp_seq      </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>rpc           </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>ip_proto      </td><td><font color='green'>Yes</font></td><td>              </td></tr>
<tr><td>sameip        </td><td><font color='red'>No</font></td><td>              </td></tr>
<tr><td>stream_size   </td><td><font color='red'>No</font></td><td>              </td></tr></tbody></table>


<h2>Non-snort signature keywords</h2>

These are FreeIPS specific and very experimental<br>
<br>
<table><thead><th><b>Keyword</b></th><th><b>Status</b></th><th><b>Usage</b></th><th><b>Comment</b></th></thead><tbody>
<tr><td>latency       </td><td><font color='Green'>Yes</font></td><td>latency:1;  </td><td>Add this amount of latency</td></tr>
<tr><td>p0f           </td><td><font color='Orange'>Yes</font></td><td>p0f;        </td><td>Fingerprinting, work in progress</td></tr>