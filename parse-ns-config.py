"""
This module reads the NetScreen configuration and creates address and policy objects in ZODB which can then be used
by the filtering and conversion scripts.
"""

# Set the debug flag
__DEBUG__ = False
__FAILURES__ = 0

import time
import ZODB
import ZODB.FileStorage
import transaction
import re
import pprint
import ipaddress

pp = pprint.PrettyPrinter(indent=2)


def SetupZODB():
    storage = ZODB.FileStorage.FileStorage('data.zodb.fs')
    storage.pack(time.time(), ZODB.serialize.referencesf)
    db = ZODB.DB(storage)

    connection = db.open()
    root = connection.root()

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

    root['failures'] = list()
    return root


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
    service_re = re.compile(
        r'set service \"(?P<name>[^\"]*)\" (protocol|\+) (?P<protocol>\S+) src-port (?P<src_ports>\d*\-\d*) dst-port (?P<dst_ports>\d*-\d*)(?: timeout (?P<timeout>\S*))?$')
    icmp_service_re = re.compile(
        r'set service \"(?P<name>[^\"]*)\" (protocol|\+) (?P<protocol>icmp) type (?P<type>\d*) code (?P<code>\d*)\s*$')
    timeout_service_re = re.compile(
        r'set service \"(?P<name>[^\"]*)\" timeout (?P<timeout>\S*)$')
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
            root['failures'].append(l)
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

    if __DEBUG__ and __FAILURES__ > 0:
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
    objs = dict()

    for l in addresslines:
        if l[-3] == '/':
            m = cidr_address_re.search(l)
        else:
            m = exp_address_re.search(l)

        if m == None:
            m = re.search(r'(?P<zone_name>[^\"]*)\" \"(?P<name>[^\"]*)\"', l)

        if m == None:
            root['failures'].append(l)
            __FAILURES__ += 1
            if __DEBUG__:
                print(l)

        if m != None and 'name' in m.groupdict():
            objname = m['name']
            objs[objname] = dict()
            k = m.groupdict().copy()
            k.pop('name', None)
            objs[objname] = k

    return objs


def ConvertIPAdressObject(ip, mask):
    return ipaddress.IPv4Network(ip + '/' + mask, strict=False)


def EnrichAddressObjDict(addresses_dict):
    for item, val in addresses_dict.items():
        try:
            val['valid'] = False
            if 'net_mask' in dict(val).keys():
                val['netobj'] = ConvertIPAdressObject(
                    val['ip'], val['net_mask'])
                val['valid'] = True
            elif 'cidr_mask' in dict(val).keys():
                val['netobj'] = ConvertIPAdressObject(
                    val['ip'], val['cidr_mask'])
                val['valid'] = True
        except:
            val['netobj'] = None

    return addresses_dict

def PopulatePolicies(cnfstr):
    lines = cnfstr.splitlines()
    policies = dict()

    # Go through the first round to enumerate policies using the
    # base line 'set policy <id> from <src_zone> to <dst_zone> ....
    for l in lines:
        if l.startswith('set policy id') and ('name' in l):
            id = re.search(r'set policy id (?P<id>\d*)', l).groupdict()['id']
            policies[id] = dict()
            matchobj = re.search(r'name (?P<name>\"[^\"]*\")'
                                          +'\s*from\s*\"(?P<src_zone>[^\"]*)\"'
                                          +'\s*to\s*\"(?P<dst_zone>[^\"]*)\"'
                                          +'\s*\"(?P<src>[^\"]*)\"'
                                          +'\s*\"(?P<dst>[^\"]*)\"'
                                          +'\s*\"(?P<service>[^\"]*)\"'
                                          +'\s*(?P<action>\S+)'
                                          +'\s*(?P<log_flag>\S+)?'
                                          , l)
            if matchobj:
                policies[id].update(matchobj.groupdict())
                policies[id]['src'] = [policies[id]['src']]
                policies[id]['dst'] = [policies[id]['dst']]
                policies[id]['service'] = [policies[id]['service']]
                policies[id]['rawconfig'] = l

            else:
                __FAILURES__+=1
                if __DEBUG__:
                    print("Failure on: "+l)

    # Go through a second round to add additional sources/destinations/services from
    # set policy <id> \n set src-address|dst-address|service\nexit blocks
    for id in policies.keys():
        index = lines.index('set policy id ' + id)
        l = lines[index]
        block = [l]
        n = index + 1
        m = lines[n]
        while 'exit' not in m:
            block.append(m)
            n += 1
            m = lines[n]
        block.append(m)
        policies[id]['rawconfig'] = policies[id]['rawconfig']+'\n'+'\n'.join(block)
        for k in block:
            if k.startswith('set src-address '):
                policies[id]['src'].append(k.split('set src-address ')[1].strip('"'))
            elif k.startswith('set dst-address '):
                policies[id]['dst'].append(k.split('set dst-address ')[1].strip('"'))
            elif k.startswith('set service '):
                policies[id]['service'].append(k.split('set service ')[1].strip('"'))
        if __DEBUG__:
            print("Processed %d" % int(id))
    return policies


def ParseConfig(cnfstr):
    # Populate the service objects
    root['service'] = PopulateServices(cnfstr)
    # Populate the address objects
    addressobjs = PopulateAddresses(cnfstr)
    # Enrich the addresses and add valid IPAddress Objects
    root['address'] = EnrichAddressObjDict(addressobjs)
    root['policies'] = PopulatePolicies(cnfstr)

def CountValidAddressObjects(addressobjdict):
    validcnt = 0
    invalidcnt = 0
    for k, v in addressobjdict.items():
        if v['valid']:
            validcnt += 1
        else:
            invalidcnt += 1
    return validcnt, invalidcnt


def dumpStats(root, cnfstr):
    print("Input config has %d characters" % len(cnfstr))
    print("There are %d service objects" % len(root['service']))
    validcnt, invalidcnt = CountValidAddressObjects(root['address'])
    print("There are %d address objects with %d valid and %d invalid entries" % (
        len(root['address']), validcnt, invalidcnt))
    print("There are %d policies" % len(root['policies']))
    print("There were %d parsing failures" % __FAILURES__)


if __name__ == '__main__':
    root = SetupZODB()
    # Start actual parsing
    INPUT_FILE = 'ns-config.txt'
    inpfd = open(INPUT_FILE, 'r')
    inpcnfstr = inpfd.read()
    inpfd.close()
    ParseConfig(inpcnfstr)
    transaction.commit()
    dumpStats(root, inpcnfstr)
    if __DEBUG__:
        with open('debug-root-db.json', 'w') as out:
            pprint.pprint(dict(root.items()), stream=out, indent=2)
