# dcFinder v1.0

dcFinder is basic python script that detects domain controllers in forest enviroinment using scapy module
and DNS SRV records. In addition to detect hostname of domain controller, you can find Primary DC that is included in a specific site.

Query types: site, primarydc, globalcatalogdc, nonglobalcatalogdc, kerberos
```
SRV Records:
_ldap._tcp.<SiteName>._sites.dc.<DNSDomainName>
_ldap._tcp.pdc._msdcs.<DNSDomainName>
_ldap._tcp.gc._msdcs.<DNSDomainName>
_ldap._tcp.dc._msdcs.<DNSDomainName>
_kerberos._tcp.dc._msdcs.<DNSDomainName>https://github.com/passtheticket/dcFinder/blob/main/images/1.PNG)
```

```
USAGE:
Use globalcatalogdc option to detect DCs in the Forest.
Example : python3 dcFinder.py --lookup --domain offensive.local --query globalcatalogdc
Use nonglobalcatalogdc option to check if there are Domain Controller(s) non-global catalog or not.
Example : python3 dcFinder.py --lookup --domain offensive.local --query nonglobalcatalogdc
Use site option to detect DC in the site.
Example : python3 dcFinder.py --lookup --domain offensive.local --query site --sitename gotham
Use kerberos option, if you have issue with ldap srv query for finding domain controller.
Example : python3 dcFinder.py --lookup --domain offensive.local --query kerberos
```

   ![alt text](https://github.com/passtheticket/dcFinder/blob/main/images/1.PNG)
