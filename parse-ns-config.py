"""
This module reads the NetScreen configuration and creates address and policy objects in ZODB which can then be used
by the filtering and conversion scripts.
"""

#Set the debug flag
__DEBUG__ = True


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
    pp.pprint(dict(root.items()))
    input()

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
INPUT_FILE = 'ns-config.txt'
inpfd = open(INPUT_FILE, 'r')
inpcnfstr = inpfd.read()
inpfd.close()

if __DEBUG__:
    print("Input config has %d characters" % len(inpcnfstr))

def populate_services(cnfstr):
    """

    :param inpcnfstr:
    :return:
    """
    lines = cnfstr.splitlines()
    failures = 0
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
        else:
            failures += 1
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

    if __DEBUG__ and failures>0:
        print("Failure count in populate_services(): %d" % failures)

    return objs

root['service'] = populate_services(inpcnfstr)
for service in root['service'].keys():
    if len(root['service'][service]) > 1:
        pp.pprint(root['service'][service])
print("There are %d service objects" % len(root['service']))
transaction.commit()





