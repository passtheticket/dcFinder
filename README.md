# dcFinder v1.0
```
            Additional Description:
            Use nonglobalcatalogdc option to check if there are Domain Controller(s) non-global catalog
            Examples : python3 dcFinder.py --lookup --domain offensive.local --query nonglobalcatalogdc
            Use site option to detect DC in the site.
            Examples : python3 dcFinder.py --lookup --domain offensive.local --query site --sitename gotham\n
            Use kerberos option, if you have issue with ldap srv query for finding DC.\n
            Examples : python3 dcFinder.py --lookup --domain offensive.local --query kerberos
```
