"""
This module reads the NetScreen configuration and creates address and policy objects in ZODB which can then be used
by the filtering and conversion scripts.
"""

#Set the debug flag
__DEBUG__ = True
__FAILURES__ = 0

import ZODB, ZODB.FileStorage
import transaction
import re
import pprint

pp = pprint.PrettyPrinter(indent=2)

storage = ZODB.FileStorage.FileStorage('data.zodb.fs')
db = ZODB.DB(storage)

connection = db.open()
root = connection.root()

if __DEBUG__:
    with open('debug-root-db.txt', 'w') as out:
        pprint.pprint(dict(root.items()), stream=out, indent=2)

# Initialize the dictionaries.
if 'policies' not in dict(root.items()):
    root['policies'] = dict()
if 'address' not in dict(root.items()):
    root['address'] = dict()
if 'addrgrp' not in dict(root.items()):
    root['addrgrp'] = dict()
if 'service' not in dict(root.items()):
    root['service'] = dict()
if 'servicegrp' not in dict(root.items()):
    root['servicegrp'] = dict()

#Start actual parsing
INPUT_FILE = 'fwry81-20170315-conf.txt'
inpfd = open(INPUT_FILE, 'r')
inpcnfstr = inpfd.read()
inpfd.close()

if __DEBUG__:
    print("Input config has %d characters" % len(inpcnfstr))

def PopulateServices(cnfstr):
    """

    :param inpcnfstr:
    :return:
    """
    global __FAILURES__
    lines = cnfstr.splitlines()

    servicelines = list()
    for l in lines:
        l = l.strip()
        if l.startswith('set service '):
            servicelines.append(l)
    service_re = re.compile(r'set service \"(?P<name>[^\"]*)\" (protocol|\+) (?P<protocol>\S+) src-port (?P<src_ports>\d*\-\d*) dst-port (?P<dst_ports>\d*-\d*)(?: timeout (?P<timeout>\S*))?$')
    icmp_service_re = re.compile(r'set service \"(?P<name>[^\"]*)\" (protocol|\+) (?P<protocol>icmp) type (?P<type>\d*) code (?P<code>\d*)\s*$')
    timeout_service_re = re.compile(r'set service \"(?P<name>[^\"]*)\" timeout (?P<timeout>\S*)$')
    results = list()
    objs = dict()
    for l in servicelines:
        if 'icmp' in l:
            m = icmp_service_re.search(l)
        elif ('timeout' in l) and not (('protocol' in l) or (' + ' in l)):
            m = timeout_service_re.search(l)
        else:
            m = service_re.search(l)
        if m and len(m.groupdict()):
            results.append(m.groupdict())
        elif re.match(r'set service \"[^\"]*\"\s*$', l):
            pass
        else:
            __FAILURES__ += 1
            if __DEBUG__:
                print(l)

    objs = dict()

    # super unoptimal but works
    for i in results:
        objname = i['name']
        objs[objname] = list()
    while results != []:
        for i in results:
            objname = i['name']
            k = i.copy()
            k.pop('name', None)
            objs[objname].append(k)
            results.remove(i)

    if __DEBUG__ and __FAILURES__> 0:
        print("Failure count in PopulateServices(): %d" % __FAILURES__)

    return objs

def PopulateAddresses(cnfstr):
    global __FAILURES__
    lines = cnfstr.splitlines()

    addresslines = list()
    for l in lines:
        l = l.strip()
        if l.startswith('set address '):
            addresslines.append(l)
    exp_address_re = re.compile(
        r'set address \"(?P<zone_name>[^\"]*)\" \"(?P<name>\S*)\" (?P<ip>\S*) (?P<net_mask>\S*)$')
    cidr_address_re = re.compile(
        r'set address \"(?P<zone_name>[^\"]*)\" \"(?P<name>\S*)\" (?P<ip>[^\/]*)/(?P<cidr_mask>\d{1,2})$')
    results = list()
    objs = list()

    for l in addresslines:
        if l[-3] == '/':
            m = cidr_address_re.search(l)
        else:
            m = exp_address_re.search(l)
        if m == None:
            print(l)
            __FAILURES__+=1
        else:
            objs.append(m.groupdict())

    return objs

def EnrichAddressObjDict(addresses_dict):
    return addresses_dict

def ConvertIPAdressObject(json_obj):
    return None



# Populate the service objects
root['service'] = PopulateServices(inpcnfstr)

#Populate the address objects
root['address'] = PopulateAddresses(inpcnfstr)

#Enrich the addresses and add valid IPAddress Objects
root['address'] = EnrichAddressObjDict(root['address'])

if __DEBUG__:
    for service in root['address']:
        if len(root['address']) > 1:
            for i in root['address']:
                if 'cidr_mask' in i.keys():
                    pp.pprint(i)
                    input()
                else:
                    pp.pprint(i)

print("There are %d service objects" % len(root['service']))
print("There were %d parsing failures" % __FAILURES__)
transaction.commit()





