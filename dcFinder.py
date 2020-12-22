#!/usr/bin/python3
import argparse
import sys
from argparse import ArgumentParser, Namespace
import scapy.all
from colorama import Fore, Style
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, ICMP, IP


class service_query:
    print(Fore.YELLOW + Style.BRIGHT +
          '''
\t+-+-+-+-+-+-+-+-+ +-+-+-+-+
\t|d|c|F|i|n|d|e|r| |v|1|.|0|
\t+-+-+-+-+-+-+-+-+ +-+-+-+-+
\t__@passtheticket__
          '''
          + Style.RESET_ALL)

    def main(self):
        try:
            dsc = "Find Domain Controllers using SRV records."
            parser: ArgumentParser = argparse.ArgumentParser(description=dsc)
            parser.add_argument("--lookup", help="srv lookup", action="store_true")
            parser.add_argument("--domain", help="Domain name", type=str, required=True)
            parser.add_argument("--query", help="Query types: site, primarydc, globalcatalogdc, nonglobalcatalogdc, kerberos", type=str, required=True)
            parser.add_argument("--sitename", help="Site name", type=str, required=False)
            parser.add_argument("--usage", help="Usage of dcFinder tool", type=str, default=True)
            args: Namespace = parser.parse_args()
            if args.lookup:
                if args.domain:
                    domain = args.domain
                    if args.query:
                        query = args.query
                        packetf = IP(dst=domain) / ICMP()
                        send = scapy.all.sr1(packetf, verbose=0, timeout=10)
                        receive = send[0].src
                        print(Fore.GREEN + Style.BRIGHT + '[+] Domain name was resolved as: %s' % receive)
                        if args.query == "site":
                            sitename = args.sitename
                            self.siteResolution(domain, sitename, query, send, receive)
                        elif args.query == "primarydc":
                            self.pdcResolution(domain, query, send, receive)
                        elif args.query == "globalcatalogdc":
                            self.globalcatalogdc(domain, query, send, receive)
                        elif args.query == "nonglobalcatalogdc":
                            self.nonglobalcatalogdc(domain, query, send, receive)
                        elif args.query == "kerberos":
                            self.kerberosResolution(domain, query, send, receive)
                        else:
                            print(Fore.RED + Style.BRIGHT + '[-] Check your syntax of query type')
                            self.dcFinderUsage()
                    else:
                        self.dcFinderUsage()
                else:
                    self.dcFinderUsage()
            else:
                self.dcFinderUsage()

        except OSError:
            print(Fore.RED + Style.BRIGHT + '[-] Domain name was not resolved.')
            print(Fore.RED + Style.BRIGHT + '[-] Check your configuration which DNS server IP address of %s domain is set, please.' % domain)
            sys.exit(Fore.RED + '[-] One bad day!')
        except TypeError:
            print(Fore.RED + Style.BRIGHT + '[-] IP address of name server is not detected.')
            sys.exit(Fore.RED + '[-] One bad day!')

    def siteResolution(self, domain, sitename, query, send, receive):
        if send:
            try:
                print(Fore.GREEN + Style.BRIGHT + '[+] Name Server is up, SRV records for: ' + sitename)
                print(Fore.GREEN + Style.BRIGHT + '[+] Domain Controller: ' + Style.RESET_ALL)
                # _ldap._tcp.<SiteName>._sites.dc.<DNSDomainName> - specific site Domain Controller
                packet = IP(dst=receive) / UDP(sport=1337, dport=53) / DNS(rd=1, qd=DNSQR(qname="_ldap._tcp.%s._sites.dc._msdcs.%s" % (sitename, domain), qtype="SRV"))
                answer = scapy.all.sr1(packet, verbose=0, timeout=2)
                siteRec = str(answer["DNSRR"].show())
                print(siteRec)
            except:
                print(str(answer["DNS"].show()))
                print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")
                sys.exit(0)

        else:
            print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")

    def pdcResolution(self, domain, query, send, receive):
        if send:
            try:
                print(Fore.GREEN + Style.BRIGHT + '[+] Name Server is up, SRV records for ' + query)
                print(Fore.GREEN + Style.BRIGHT + '[+] Primary Domain Controller: '+ Style.RESET_ALL)
                # _ldap._tcp.pdc._msdcs.<DNSDomainName> - Primary Domain Controller (PDC)
                packet = IP(dst=receive) / UDP(sport=1337, dport=53) / DNS(rd=1, qd=DNSQR(qname="_ldap._tcp.pdc._msdcs.%s" % domain, qtype="SRV"))
                answer = scapy.all.sr1(packet, verbose=0, timeout=2)
                pdc = str(answer["DNSRR"].show())
                print(pdc)
            except:
                print(str(answer["DNS"].show()))
                print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")
                sys.exit(0)
        else:
            print(Fore.RED + '[-] Destination Unreachable!')

    def globalcatalogdc(self, domain, query, send, receive):
        if send:
            try:
                print(Fore.GREEN + Style.BRIGHT + '[+] Name Server is up, SRV records for: ' + domain)
                print(Fore.GREEN + Style.BRIGHT + '[+] Global Catalog Domain Controller: '+ Style.RESET_ALL)
                # _ldap._tcp.gc._msdcs.<DNSDomainName> - Global Catalog Domain Controller (GC)
                packet = IP(dst=receive) / UDP(sport=1337, dport=53) / DNS(rd=1, qd=DNSQR(qname="_ldap._tcp.gc._msdcs.%s" % domain, qtype="SRV"))
                answer = scapy.all.sr1(packet, verbose=0, timeout=2)
                gcdc = str(answer["DNSRR"].show())
                print(gcdc)
            except:
                print(str(answer["DNS"].show()))
                print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")
                sys.exit(0)
        else:
            print(Fore.RED + '[-] Destination Unreachable!')

    def nonglobalcatalogdc(self, domain, query, send, receive):
        if send:
            try:
                print(Fore.GREEN + Style.BRIGHT + '[+] Name Server is up, SRV records for: ' + domain)
                print(Fore.GREEN + Style.BRIGHT + '[+] Domain Controller: '+ Style.RESET_ALL)
                # _ldap._tcp.dc._msdcs.<DNSDomainName> - Domain Controller (non-GC)
                packet = IP(dst=receive) / UDP(sport=1337, dport=53) / DNS(rd=1, qd=DNSQR(qname="_ldap._tcp.dc._msdcs.%s" % domain, qtype="SRV"))
                answer = scapy.all.sr1(packet, verbose=0, timeout=2)
                nongcdc = str(answer["DNSRR"].show())
                print(nongcdc)
            except:
                print(str(answer["DNS"].show()))
                print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")
                sys.exit(0)

        else:
            print(Fore.RED + '[-] Destination Unreachable!')

    def kerberosResolution(self, domain, query, send, receive):
        if send:
            try:
                print(Fore.GREEN + Style.BRIGHT + '[+] Name Server is up, SRV records for ' + query)
                print(Fore.GREEN + Style.BRIGHT + '[+] Key Distribution Center: '+ Style.RESET_ALL)
                # _kerberos._tcp.dc._msdcs.<DNSDomainName> - Using kerberos (KDC)
                packet = IP(dst=receive) / UDP(sport=1337, dport=53) / DNS(rd=1, qd=DNSQR(qname="_kerberos._tcp.dc._msdcs.%s" % domain, qtype="SRV"))
                answer = scapy.all.sr1(packet, verbose=0, timeout=2)
                krbrs = str(answer["DNSRR"].show())
                print(krbrs)
            except:
                print(str(answer["DNS"].show()))
                print(Fore.RED + Style.BRIGHT + "[-] Record was not found!")
                sys.exit(0)

        else:
            print(Fore.RED + '[-] Destination Unreachable!')

    def dcFinderUsage(self):
        print(
            Fore.WHITE + Style.BRIGHT +'USAGE :\n' +
            Fore.RED +	'query types: site, primarydc, globalcatalogdc, nonglobalcatalogdc, kerberos\n' +
            Fore.WHITE +	'Use globalcatalogdc option to detect DCs in the Forest.\n' +
            Fore.WHITE +	'Example : python3 dcFinder.py --lookup --domain offensive.local --query globalcatalogdc'
        )
        sys.exit(0)

srv = service_query()
if __name__ == '__main__':
    srv.main()
