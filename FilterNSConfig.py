"""
This module reads the NetScreen configuration and creates address and policy objects in ZODB which can then be used
by the filtering and conversion scripts.

Author:     Fahad Yousuf <fahadysf@gmail.com>

Copyright (c) 2017 Fahad Yousuf <fahadysf@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

SUBNETS_TO_FILTER = ["172.20.232.0/25", "172.20.111.0/24"]

import ipaddress
import pprint
from ParseNetscreenConfig import SetupZODB

pp = pprint.PrettyPrinter(indent=2)

class PolicyFilter():

    def __init__(self):
        self.root = SetupZODB()

    def GetRelatedServices(self,polid):
        return

    def GetRelatedAddresses(self,polid):
        return

    def CheckPolicy(self, subnet, polid):
        return

    def FindPolicies(self, subnetstr):
        netaddr = ipaddress.IPv4Network(subnetstr)
        pols = self.root['policies']
        matching_pols = list()
        matching_pols_addresses = set()
        matching_pols_services = set()
        for p in pols:
            pobj = pols[p]
            srcaddrs = pobj['src']
            dstaddrs = pobj['dst']
            services = pobj['service']
            pol_match = False
            for i in srcaddrs+dstaddrs:
                if pol_match:
                    break
                if i in self.root['addrgrp'].keys():
                    addrs = self.root['addrgrp'][i]
                    for k in addrs:
                        if k != 'Any':
                            if self.root['address'][k]['valid']:
                                taddr = self.root['address'][k]['netobj']
                                if taddr.overlaps(netaddr):
                                    matching_pols.append(pobj)
                                    matching_pols_addresses = matching_pols_addresses.union(set(srcaddrs + dstaddrs))
                                    matching_pols_services = matching_pols_services.union(set(services))
                                    pol_match = True
                elif i != 'Any' and i in self.root['address'].keys():
                    if self.root['address'][i]['valid']:
                        taddr = self.root['address'][i]['netobj']
                        if taddr.overlaps(netaddr):
                            matching_pols.append(pobj)
                            matching_pols_addresses = matching_pols_addresses.union(set(srcaddrs + dstaddrs))
                            matching_pols_services = matching_pols_services.union(set(services))
                            pol_match = True

        return list(matching_pols_services),\
               list(matching_pols_addresses),\
               matching_pols

if __name__ == '__main__':
    pf = PolicyFilter()
    for i in SUBNETS_TO_FILTER:
        services, addresses, policies = pf.FindPolicies(i)
        for s in services:
            if s in pf.root['service'].keys():
                for item in pf.root['service'][s]:
                    print(item['rawconfig'])
        for a in addresses:
            if a in pf.root['address'].keys():
                print(pf.root['address'][a]['rawconfig'])
        for p in policies:
            print(p['rawconfig'])