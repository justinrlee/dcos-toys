#!/opt/mesosphere/bin/python
### Should point to python on a DC/OS master node.  Otherwise, relies on python3.5

import sys
sys.path.append('/opt/mesosphere/lib/python3.5/site-packages')

import argparse
import socket
import sys
import time
import requests
import getpass
import json
import os
import copy
# Using requests's built-in json parser

# Disable auth InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Hack to get working in proxy environment (basically ignores proxy)
session = requests.Session()
session.trust_env = False

RESOURCE_STRING = "    {resource:<12}:{allocated:>12.2f} / {total:<12.2f} {unit:<8} {percentage:>6.2f} %"
CONTAINER_RESOURCE_STRING = "            {resource:<4}:{used:>8.2f} / {allocated:<8.2f} {unit:<8} {percentage:>6.2f} %"
ROLE_RESOURCE_STRING = "        {role:<20}: {amount:<12.2f} {unit:<8}"
ROLE_STRING = "        {role}:"
RESERVATION_STRING = "            {reservation_id:<40} {amount:<12.2f}      [{principal:^24}]"

SINGLE_PORT_RESOURCE_STRING =   "     - {port:<5}"
SINGLE_PORT_RESOURCE_STRING_ROLE =   "     - {port:<5}                [{role:^20}]"
PORT_RESOURCE_STRING =          "     - {start:<5} - {end:<5}"
PORT_RESOURCE_STRING_ROLE =          "     - {start:<5} - {end:<5}        [{role:^20}]"

FRAMEWORK_STRING = "{id:<51} [{name:^26}]"

VERSION = 0.5

CSV_UTILIZATION_STRING = "{node},{ip},{task},{cpus_used},{cpus_allocated},{cpus_utilization},{memory_used},{memory_allocated},{memory_utilization}"

CSV_MODE = False

def cprint(x):
    if not CSV_MODE:
        print(x)

# Used for CSV printing
def Cprint(x):
    if CSV_MODE:
        print(x)

def dp(x):
    print(x)

def lpad(str, int = 4):
    cprint("{}{}".format(" "*int, str))


def dget(item, ks, default):
    if len(ks) == 1:
        if ks[0] in item:
            return item[ks[0]]
        else:
            return default
    else:
        if ks[0] in item and item[ks[0]] is not None:
            return dget(item[ks[0]],ks[1:],default)
        else:
            return default


def get_auth_token(hostname, username, password):
    if hostname is None:
        hostname = socket.gethostname()
    headers = {'content-type': 'application/json'}
    data = {'uid': username, 'password': password}
    response = session.post("https://{hostname}/acs/api/v1/auth/login".format(hostname=hostname),
                             headers=headers,
                             data=json.dumps(data),
                             verify=False).json()
    token = response['token'] if 'token' in response else None
    return token


def login(hostname = None):
    if hostname is None:
        hostname = socket.gethostname()
    token = None
    try:
        while not token:
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            token =  get_auth_token(hostname, username, password)
    except KeyboardInterrupt:
        exit(1)
    return token


'''.json() Doesn't actually return json - it's roughly equivalent to json.loads'''
def get_json(url):
    req = session.get(url)
    return req.json()

def get_slaves(hostname = None):
    if hostname is None:
        hostname = socket.gethostname()
    port = 5050

    slaves_url = "http://{hostname}:{port}/slaves".format(hostname=hostname, port=port)

    return get_json(slaves_url)

def get_state_json(hostname = None):
    if hostname is None:
        hostname = socket.gethostname()
    port = 5050

    url = "http://{hostname}:{port}/state.json".format(hostname=hostname, port=port)

    return get_json(url)

def get_statistics(hostname):
    port = 5051

    containers_url = "http://{hostname}:{port}/monitor/statistics.json".format(
        hostname=hostname, port=port)

    try:
        containers = get_json(containers_url)
    except:
        print("Unable to connect to slave at {}.".format(containers_url))
        containers = None
    return containers


def get_marathon_apps(hostname, token):
    if hostname is None:
        hostname = socket.gethostname()
    headers = {'authorization': "token={token}".format(token=token)}
    response = session.get("http://{hostname}/marathon/v2/apps".format(hostname=hostname),
                 headers=headers)
    not_json = response.json()
    return not_json['apps'], response.text

def print_marathon_apps(apps, level, show_inactive):
    app_dict = {app['id']:app for app in apps}
    for app_id in sorted(app_dict.keys()): # Need to implement sorting
        app = app_dict[app_id]
        if app['instances'] > 0 or show_inactive == True:
            # print(app_id)
            print_app(app, level)
            # print(app_dict[app_id])
            # print(json.dumps(app_dict[app_id]))
            cprint("")

def print_app(app, level):
    resource_string="    {resource:<8}: {amount:<6} {unit:<6} "
    
    print_separator(80, '-')

    # print(json.dumps(app))
    # print_separator(40, '-')

    if app['instances'] == 0:
        cprint("{app:<40} ** INACTIVE **".format(app=app['id']))
    else:
        cprint("{app:<40} ** ACTIVE [{running} Tasks Running] **".format(app=app['id'], running=app['tasksRunning']))
    print_separator(80, '-')
    # print("{id}".format(id=app['id']))
    lpad("Roles:           {}".format('*' if 'acceptedResourceRoles' not in app or app['acceptedResourceRoles'] == None else 
                                       app['acceptedResourceRoles'] if len(app['acceptedResourceRoles']) == 1 else 
                                       ','.join(app['acceptedResourceRoles'])))
    cprint("")    
    lpad("Docker Image:    {}".format(dget(app,['container','docker','image'],'N/A')))
    cprint("")
    lpad("Command:")
    lpad("{}".format(app['cmd']),8)
    cprint("")
    # print("Resources:")
    lpad("{} Instance(s), each with:".format(app['instances']))
    if app['cpus'] > 0:
        lpad(resource_string.format(amount=app['cpus'], unit='Cores', resource='CPU'))
    if app['gpus'] > 0:        
        lpad(resource_string.format(amount=app['gpus'], unit='Cores', resource='GPU'))
    if app['mem'] > 0:        
        lpad(resource_string.format(amount=app['mem'], unit='MB', resource='Memory'))
    if app['disk'] > 0:        
        lpad(resource_string.format(amount=app['disk'], unit='MB', resource='Disk'))
    # print("    {cpus:<4} Cores".format(cpus=app['cpus']))
    # print("    {} GPU Core".format(gpus=app['gpus']))
    # print("    {} MB Memory".format(mem=app['mem']))
    # print("    {} MB Disk".format(disk=app['disk']))
    # print("          {} Cores\n, {} GPUs\n, {} MB Memory\n, {} MB Disk\n".format(app['cpus'], app['gpus'], app['mem'], app['disk']))
    cprint("")
    if len(app['ports']) > 0 and len(app['ports']) < 10:
        lpad("Ports:")
        for port in app['ports']:
            lpad(" - {}".format(port))
        cprint("")
    elif len(app['ports']) >= 10:
        lpad("Ports: " + ','.join(str(x) for x in app['ports']))
        cprint("")

    if len(app['uris']) > 0:
        lpad("URIs:")
        for uri in app['uris']:
            lpad(" - {}".format(uri),4)
    if level > 1:
        if len(app['env']) > 0:
            cprint("")
            lpad("Environment Variables:")
            for v in sorted(app['env']):
                lpad("\"{}\" : \"{}\"".format(v, app['env'][v]), 8)
        if len(app['labels']) > 0:
            cprint("")
            lpad("Labels:")
            for v in sorted(app['labels']):
                lpad("\"{}\" : \"{}\"".format(v, app['labels'][v]), 8)



def print_separator(length = 80, k = '=', spaces = 0):
    cprint(" " * spaces + k * length)

# Expects a start and end dict, each containing at least these fields:
    #   "cpus_limit"
    #   "mem_limit_bytes"
    #   "cpus_system_time_secs"
    #   "cpus_user_time_secs"
    #   "mem_rss_bytes"
    #   "timestamp"
    #
    # We look at cpu time over time period, and memory at latest time point.
def calculate_container_stats(start, end):
    stats = {}

    timestamp_delta = end['timestamp'] - start['timestamp']

    # print(end)
    stats['memory_allocated'] = end['mem_limit_bytes']
    stats['memory_used'] = end['mem_rss_bytes']
    stats['memory_utilization'] = 100.0 * end['mem_rss_bytes'] / end['mem_limit_bytes']

    cpus_time_delta = (end['cpus_system_time_secs'] + end['cpus_user_time_secs']
                       - start['cpus_system_time_secs'] - start['cpus_user_time_secs'])
    if(abs(cpus_time_delta) < 1e-12) or timestamp_delta == 0:
        cpus_time_delta = 0
        timestamp_delta = 1
    stats['cpus_used'] = float(cpus_time_delta / timestamp_delta)
    stats['cpus_allocated'] = end['cpus_limit']
    stats['cpus_utilization'] = 100 * stats['cpus_used'] / stats['cpus_allocated']

    return stats


#### Need to refactor to pull out calculations from prints
#### Also need to refactor to rearrange function
# Memory and disk in megabytes, percentage already multiplied by 100
def print_stats(allocated, total, percentage):
    cprint("    [Resource]  : [Allocated] / [Total]      [Units]  [Percentage]")

    if total['cpus'] > 0:
        cprint(RESOURCE_STRING.format(resource = "CPU", 
                            allocated = allocated['cpus'], 
                            total = total['cpus'], 
                            percentage = percentage['cpus'],
                            unit = "Cores"))

    if total['mem'] > 0:
        cprint(RESOURCE_STRING.format(resource = "Memory", 
                            allocated = allocated['mem'], 
                            total = total['mem'], 
                            percentage = percentage['mem'],
                            unit = "MB"))

    # Consider adjusting for GB:
    if total['disk'] > 0:
        cprint(RESOURCE_STRING.format(resource = "Disk", 
                            allocated = allocated['disk'], 
                            total = total['disk'], 
                            percentage = percentage['disk'],
                            unit = "MB"))

    if total['gpus'] > 0:
        cprint(RESOURCE_STRING.format(resource = "GPU", 
                            allocated = allocated['gpus'], 
                            total = total['gpus'], 
                            percentage = percentage['gpus'],
                            unit = "Cores"))
        
    cprint("")

# Collect information (totals) about a cluster from a 'slaves' block (and display it)
def print_cluster_stats(slaves):
    resources = ['mem', 'cpus', 'gpus', 'disk']

    total = {}
    allocated = {}
    percentage = {}
    for resource in resources:
        total[resource] = sum([slave['resources'][resource] for slave in slaves['slaves']])
        allocated[resource] = sum([slave['used_resources'][resource] for slave in slaves['slaves']])
        percentage[resource] = 0 if total[resource] == 0 else 100 * allocated[resource] / total[resource]

    print_separator()
    cprint("Cluster:")
    print_separator()

    print_stats(allocated, total, percentage)

# Rerrange stats about a slave from a 'slaves' block (and display it).
def print_slave_stats(slave):
    allocated = {}
    total = {}
    percentage = {}

    resources = ['mem', 'cpus', 'gpus', 'disk']

    for resource in resources:
        total[resource] = slave['resources'][resource]
        allocated[resource] = slave['used_resources'][resource]
        percentage[resource] = 0 if slave['resources'][resource] == 0 else (
            100.0 * slave['used_resources'][resource] / slave['resources'][resource])

    print_stats(allocated, total, percentage)

# Based on a resource blob, will return two items:
# A summary reservation list, by type then role (sum per each grouping)
# A list of actual reservations, by type then role (individual reservations)
def aggregate_resource_list(blob):
    resources = {
    }
    resource_reservations = {
    }

    # print_separator(24,'+')
    # print("starting blob:")
    # print(blob)
    # print_separator(24,'+')


    for item in blob:
        
        # Create resource types:
        if item['name'] not in resources:
            resources[item['name']] = {}
        if item['name'] not in resource_reservations:
            # print("Adding role {} to resource reservations".format(item['name']))
            resource_reservations[item['name']] = {}

        # print("Pulling item:")
        # print(item['name'])
        # print(item)
        # print("")

        #### Rewrite starts here

        if item['type'] == 'SCALAR':
            if 'role' in item: # Regular reservation

                # Add to the resource summary
                if item['role'] not in resources[item['name']]:
                    resources[item['name']][item['role']] = item['scalar']['value']
                else:
                    resources[item['name']][item['role']] += item['scalar']['value']

                if 'reservation' in item:
                    # print("processing reservation for ")
                    # print(item)
                    # Make sure type/role element exists in resource_reservations
                    if item['role'] not in resource_reservations[item['name']]:
                        resource_reservations[item['name']][item['role']] = []

                    new_reservation = {'amount': item['scalar']['value'],
                            'resource_id': item['reservation']['labels']['labels'][0]['value'],
                            'principal': item['reservation']['principal']}

                    # If persistent volume, note info
                    if 'disk' in item and 'persistence' in item['disk']:
                        new_reservation['container_path'] = item['disk']['volume']['container_path']
                        new_reservation['volume_id'] = item['disk']['persistence']['id']
                    
                    resource_reservations[item['name']][item['role']].append(new_reservation)


                if 'reservations' in item:
                    # Eventually move above processing to here:
                    dynamic_reservations = [reservation for reservation in item['reservations'] if reservation['type'] == 'DYNAMIC']
                    if len(dynamic_reservations) > 0:
                        # print("Dynamic reservation:")
                        # # print(item)
                        # print(dynamic_reservations[0])

                        # if 'persistence' in dynamic_reservations[0]:
                        # # if item['name'] == 'disk' and :
                        #     print("Do disk processing for:")
                        #     print(dynamic_reservations[0])
                        #     # print(item)
                        pass                

            else: # Fancy reservation - should always have 'reservations'.  If not, logic is wrong
                # dp(item)
                # if 'reservations' in item:
                static_reservation = [r for r in item['reservations'] if r['type'] == 'STATIC'][0]
                dynamic_reservation = [r for r in item['reservations'] if r['type'] == 'DYNAMIC'][0]
                # dp(static_reservation)
                # dp(dynamic_reservation)

                # Use static reservation for summary, dynamic for reservation
                if static_reservation['role'] not in resources[item['name']]:
                    resources[item['name']][static_reservation['role']] = item['scalar']['value']
                else:
                    resources[item['name']][static_reservation['role']] += item['scalar']['value']

                #
                if dynamic_reservation['role'] not in resource_reservations[item['name']]:
                    resource_reservations[item['name']][dynamic_reservation['role']] = []

                new_reservation = {'amount': item['scalar']['value'],
                        'resource_id': dynamic_reservation['labels']['labels'][0]['value'],
                        'principal': dynamic_reservation['principal']}

                # If persistent volume, note info
                if 'disk' in item and 'persistence' in item['disk']:
                    new_reservation['container_path'] = item['disk']['volume']['container_path']
                    new_reservation['volume_id'] = item['disk']['persistence']['id']
                
                resource_reservations[item['name']][dynamic_reservation['role']].append(new_reservation)

                    # role = item['reservations'][1]
                # else:
                #     dp("No reservations?")



        elif item['type'] == 'RANGES':
            # print_separator(8,'|')
            # print("processing:")
            # print(item)
            # desired:
            #  - resources['cpu']['hdfs-principal'] = []
            #  - resource_breakdowns['cpu']['hdfs-principal] = [] (list of dicts)

            if 'role' in item: # Regular reservation

                if item['role'] not in resources[item['name']]:
                    resources[item['name']][item['role']] = copy.deepcopy(item['ranges']['range'])
                else:
                    resources[item['name']][item['role']] += item['ranges']['range']

                # Make sure type/role element exists in resource_reservations
                if item['role'] not in resource_reservations[item['name']]:
                    resource_reservations[item['name']][item['role']] = []

                if 'reservation' in item:
                    new_dict = {'ranges': item['ranges']['range'], 'resource_id': item['reservation']['labels']['labels'][0]['value']}
                    resource_reservations[item['name']][item['role']].append(new_dict)


            else:
                static_reservation = [r for r in item['reservations'] if r['type'] == 'STATIC'][0]
                dynamic_reservation = [r for r in item['reservations'] if r['type'] == 'DYNAMIC'][0]

                if static_reservation['role'] not in resources[item['name']]:
                    resources[item['name']][static_reservation['role']] = copy.deepcopy(item['ranges']['range'])
                else:
                    resources[item['name']][static_reservation['role']] += item['ranges']['range']

                # Make sure type/role element exists in resource_reservations
                if dynamic_reservation['role'] not in resource_reservations[item['name']]:
                    resource_reservations[item['name']][dynamic_reservation['role']] = []

                # if 'reservations' in item:
                new_dict = {'ranges': item['ranges']['range'], 'resource_id': dynamic_reservation['labels']['labels'][0]['value']}
                # dp(new_dict)
                resource_reservations[item['name']][dynamic_reservation['role']].append(new_dict)

                # dp(item)
                # dp("")


    if False:

        #### end rewrite
        if 'role' in item and item['role'] not in resource_reservations[item['name']]:
            # print("-----Creating empty list for resource_reservations[{}][{}]".format(item['name'],item['role']))
            resource_reservations[item['name']][item['role']] = []
        
        print('done')
        # print(resource_reservations[item['name']][item['role']])

        # Process scalar items here; otherwise, process as range
        if item['type'] == 'SCALAR':
            # desired:
            #  - resources['cpu']['hdfs-principal'] = 3 (scalar)
            #  - resource_breakdowns['cpu']['hdfs-principal] = [] (list of dicts)
            
            # Populate values in resource types
            if item['role'] not in resources[item['name']]:
                resources[item['name']][item['role']] = item['scalar']['value']
            else:
                resources[item['name']][item['role']] += item['scalar']['value']

            # At some point, may switch from the 'reservation' field to the 'reservations' field.
            if 'reservations' in item:
                # for reservation in item['reservations']:
                #     res = {
                #         'amount': 
                #     }
                #     resource_reservations[item['name']][item['role']].append(res)
                resource_reservations[item['name']][item['role']].append(
                        {'amount': item['scalar']['value'],
                        'resource_id': item['reservation']['labels']['labels'][0]['value'],
                        'principal': item['reservation']['principal']}
                )
        
            # print(resource_reservations[item['name']][item['role']])

        elif item['type'] == 'RANGES':
            # print_separator(8,'|')
            # print("processing:")
            # print(item)
            # desired:
            #  - resources['cpu']['hdfs-principal'] = []
            #  - resource_breakdowns['cpu']['hdfs-principal] = [] (list of dicts)
            if item['role'] not in resources[item['name']]:
                resources[item['name']][item['role']] = copy.deepcopy(item['ranges']['range'])
            else:
                resources[item['name']][item['role']] += item['ranges']['range']

            if 'reservation' in item:
                new_dict = {'ranges': item['ranges']['range'], 'resource_id': item['reservation']['labels']['labels'][0]['value']}
                resource_reservations[item['name']][item['role']].append(new_dict)

        
        # print(resource_reservations[item['name']][item['role']])


    return resources, resource_reservations

# tech debt galore; role isn't used.
def print_resource_by_roles(label, unused, aggregate_resource, unit):
    lpad("{label} ({unit}):".format(label=label, unit=unit))
    total = 0
    for role in aggregate_resource:

        cprint(ROLE_RESOURCE_STRING.format(role=role, amount=aggregate_resource[role], unit=""))
        total += aggregate_resource[role]
    
    print_separator(length = 32, k = '-', spaces = 8)
    cprint(ROLE_RESOURCE_STRING.format(role="Total", amount=total, unit=unit))
    cprint("")


def print_role_breakdown(aggregate, reserved_reservations = None, get_reservation_breakdown = False):
    if 'cpus' in aggregate:
        print_resource_by_roles('CPU', 'cpus', aggregate['cpus'], "Cores")
        if get_reservation_breakdown:
            print_reservation_by_role(reserved_reservations['cpus'], 'CPU', 'Cores')

    if 'mem' in aggregate:
        print_resource_by_roles('Mem', 'mem', aggregate['mem'], "MB")
        if get_reservation_breakdown:
            print_reservation_by_role(reserved_reservations['mem'], 'Mem', 'MB')

    if 'disk' in aggregate:
        print_resource_by_roles('Disk', 'disk', aggregate['disk'], "MB")
        if get_reservation_breakdown:
            print_reservation_by_role(reserved_reservations['disk'], 'Disk', 'MB')
            # print(reserved_reservations['disk'])

    if 'gpus' in aggregate:
        print_resource_by_roles('GPU', 'gpus', aggregate['gpus'], "Cores")
        if get_reservation_breakdown:
            print_reservation_by_role(reserved_reservations['gpus'], 'GPU', 'Cores')

def print_reservation_by_role(reservation_list, label, unit):
    # print("    {label} ({unit}):".format(label=label, unit=unit))
    for role in reservation_list:
        cprint(ROLE_STRING.format(role=role))
        for reservation in reservation_list[role]:
            cprint(RESERVATION_STRING.format(reservation_id=reservation['resource_id'],
                                            amount=reservation['amount'],
                                            unit=unit,
                                            principal=reservation['principal']))
            if 'volume_id' in reservation:
                cprint("                Volume ID: {volume_id} [{path}]".format(volume_id=reservation['volume_id'],path=reservation['container_path']))
    cprint("")
        # print(reservation_list[role])

def print_port_reservation_by_role(reservation_list, label):
    # print("    {label} ({unit}):".format(label=label, unit=unit))
    for role in reservation_list:
        cprint(ROLE_STRING.format(role=role))
        for reservation in reservation_list[role]:
            lpad(reservation['resource_id'], 12)
            for r in reservation['ranges']:
                if r['begin'] == r['end']:
                    lpad(SINGLE_PORT_RESOURCE_STRING.format(port=r['begin']),8)
                else:
                    lpad(PORT_RESOURCE_STRING.format(start=r['begin'], end=r['end']),8)


def print_slave_reservations(slave, get_reservation_breakdown):
    reserved_resources_full = slave['reserved_resources_full']
    used_resources_full = slave['used_resources_full']

    # print(json.dumps(reserved_resources_full))
    # print(json.dumps(used_resources_full))

    # print(reserved_resources_full)
    combined_reserved_resources = []
    for role in reserved_resources_full:
        combined_reserved_resources += reserved_resources_full[role]
        # print_separator(10, '+')
        # print(json.dumps(reserved_resources_full[role]))
        # print("Aggregating...")
        # res = aggregate_resource_list(reserved_resources_full[role])
    # print("Aggregating combined")
    # print("Combined:")
    # print(json.dumps(combined_reserved_resources))
    # print("combined")
    # print(combined_reserved_resources)
    # print("calculating reserved")
    reserved, reserved_reservations = aggregate_resource_list(combined_reserved_resources)
    # print("r")
    # print(reserved)
    # print("r_r")
    # print(reserved_reservations)
    # print(reserved)
    # print(reserved_reservations)

    # print(used_resources_full)
    # print("Aggregating...")
    # (we don't use allocated_reservations right now)
    # print("calculating allocated")
    allocated, allocated_reservations = aggregate_resource_list(used_resources_full)


    print_separator(60, spaces=4)
    lpad("Reserved Resources (By Role):")
    print_role_breakdown(reserved, reserved_reservations, get_reservation_breakdown)
    cprint("")
    print_separator(60, spaces=4)
    lpad("Allocated Resources (By Role):")
    print_role_breakdown(allocated)

    # if get_reservation_breakdown:
    #     print_separator(60, spaces=4)
    #     print("    Resource Reservations (By Role):")
    #     print_resource_reservations(reserved_reservations)
    # print(reserved_reservations['ports'])

    cprint("")
    print_separator(60, spaces=4)

    if 'ports' not in reserved:
        reserved['ports'] = {}
    if 'ports' not in allocated:
        allocated['ports'] = {}
    if 'ports' not in reserved_reservations:
        reserved_reservations['ports'] = {}
    print_ports(slave, reserved['ports'], allocated['ports'], reserved_reservations['ports'], get_reservation_breakdown)

    
# Print information about the ports in use (one per line) / available on a slave
def print_ports(slave, reserved, allocated, reserved_reservations = None, get_reservation_breakdown = False):
    lpad("Used Ports: ")
    if 'ports' in slave['used_resources']:
        for port_range in slave['used_resources']['ports'][1:-1].split(','):
            r = port_range.strip().split('-')
            for port in range(int(r[0]), int(r[0]) + 1):
                cprint(SINGLE_PORT_RESOURCE_STRING.format(port=port))
    else:
        cprint(SINGLE_PORT_RESOURCE_STRING.format(port="{none}"))

    cprint("")
    lpad("Reserved Ports:")
    for role in reserved:
        for r in reserved[role]:
            if r['begin'] == r['end']:
                cprint(SINGLE_PORT_RESOURCE_STRING_ROLE.format(port=r['begin'],role=role))
            else:
                cprint(PORT_RESOURCE_STRING_ROLE.format(start=r['begin'],end=r['end'],role=role))

    if get_reservation_breakdown:
        cprint("")
        lpad("Reserved Ports (by Reservation):")
        print_port_reservation_by_role(reserved_reservations, 'port')
        # for role in reserved_reservations:
        #     print(role)
        #     print(reserved_reservations[role])

    cprint("")
    lpad("Allocated Ports:")
    for role in allocated:
        for r in allocated[role]:
            if r['begin'] == r['end']:
                cprint(SINGLE_PORT_RESOURCE_STRING_ROLE.format(port=r['begin'],role=role))
            else:
                cprint(PORT_RESOURCE_STRING_ROLE.format(start=r['begin'],end=r['end'],role=role))

    cprint("")
    lpad("All agent ports: ")
    for port_range in slave['resources']['ports'][1:-1].split(','):
        s,e = port_range.strip().split('-')
        cprint(PORT_RESOURCE_STRING.format(start=s,end=e))
    cprint("")


def get_entry_matching(entries, key, value):
    # print("Looking for '{}' = '{}'".format(key, value))
    for entry in entries:
        # print(entry)
        if key in entry and entry[key] == value:
            # print('value found')
            return entry
        else:
            # print("{}!={}".format(entry[key],value))
            pass
    return None

def aggregate_tasks_by_vip(tasks):
    vips = {}
    for task in tasks:
        if task['state'] == 'TASK_RUNNING' and 'discovery' in task and 'ports' in task['discovery'] and 'ports' in task['discovery']['ports']:
            for port in task['discovery']['ports']['ports']:
                # Who the hell came up with this structure?
                if 'labels' in port and 'labels' in port['labels']:
                    for label in port['labels']['labels']:
                        # print(label)
                        if 'VIP' in label['key']:
                            # print(label)
                            vip = label['value']
                            if vip[0] == '/':
                                vip = vip[1:]
                            port = port['number']
                            # Need to get ip addess.  Again, terrible structure.
                            running_status = get_entry_matching(task['statuses'], 'state', 'TASK_RUNNING')
                            network_infos = running_status['container_status']['network_infos']
                            ip = network_infos[0]['ip_addresses'][0]['ip_address']
                            if vip not in vips:
                                vips[vip] = [(ip, port)]
                            else:
                                vips[vip].append((ip,port))
    return vips

def print_minuteman(state):
    if 'frameworks' in state:
        # print('hello')
        for framework in state['frameworks']:
            print_separator()
            cprint(FRAMEWORK_STRING.format(id = framework['id'], name = framework['name']))
            if 'tasks' in framework:
                vips = aggregate_tasks_by_vip(framework['tasks'])
                for vip in vips:
                    split_vip = vip.split(':')
                    lpad("{}.{}.l4lb.thisdcos.directory:{}".format(split_vip[0], framework['name'], split_vip[1]))
                    for backend in vips[vip]:
                        lpad(" - {}:{}".format(backend[0], backend[1]))

            cprint("")
# 
def print_agent_info(slaves, get_container_stats, get_reservation_breakdown, wait = 5):
    data_start = {}
    data_end = {}
    if get_container_stats:
        for slave in slaves:
            stats = get_statistics(slave['hostname'])
            if stats is not None:
                data_start[slave['hostname']] = {
                    container['executor_id']:container for container in stats}

        # Wait between polls.  Precision not necessary.
        time.sleep(wait)
        for slave in slaves:
            stats = get_statistics(slave['hostname'])
            if stats is not None:
                data_end[slave['hostname']] = {
                    container['executor_id']:container for container in stats}

    for slave in slaves:
        hostname = slave['hostname']
        # print(slave)
        slave_type = 'slave_public' if 'public_ip' in slave['attributes'] else 'slave'
        print_separator()
        cprint("{id:<44} IP: {ip:<16} [{slave_type:^12}]".format(id=slave['id'], ip=hostname, slave_type=slave_type))
        print_separator()
        cprint("")
        
        # print(slave)

        print_slave_stats(slave)
        print_slave_reservations(slave, get_reservation_breakdown)

        if get_container_stats:
            print_separator(60, spaces=4)
            lpad("Containers: ")
            for executor in data_end[hostname]:
                if executor in data_start[hostname]:
                    stats = calculate_container_stats(data_start[hostname][executor]['statistics'], 
                                            data_end[hostname][executor]['statistics'])
                    print_separator()
                    # print(slave['id'])
                    # print(hostname)
                    # print(executor)
                    # print(stats)
                    Cprint(CSV_UTILIZATION_STRING.format(
                                                         node=slave['id'],
                                                         ip=hostname,
                                                         task=executor,
                                                         cpus_used=stats['cpus_used'],
                                                         cpus_allocated=stats['cpus_allocated'],
                                                         cpus_utilization=stats['cpus_utilization'],
                                                         memory_used=stats['memory_used'],
                                                         memory_allocated=stats['memory_allocated'],
                                                         memory_utilization=stats['memory_utilization']))
                    print_container_stats(executor, stats)
                else:
                    # If executor present in 'data_end' but not 'data_start', use data_end for both,
                    # then skip printing CPU (memory only uses data_end, CPU uses both)
                    stats = calculate_container_stats(data_end[hostname][executor]['statistics'], 
                                            data_end[hostname][executor]['statistics'])
                    print_container_stats(executor, stats, single_data_point = True)
                    Cprint(CSV_UTILIZATION_STRING.format(
                                                         node=slave['id'],
                                                         ip=hostname,
                                                         task=executor,
                                                         cpus_used="N/C",
                                                         cpus_allocated=stats['cpus_allocated'],
                                                         cpus_utilization="N/C",
                                                         memory_used=stats['memory_used'],
                                                         memory_allocated=stats['memory_allocated'],
                                                         memory_utilization=stats['memory_utilization']))

        cprint("")

# Print statistics for a given container
def print_container_stats(executor, stats, single_data_point = False):
    lpad(executor,8)
    if single_data_point:
        print("            CPU not calculated for ephemeral container")
    else:
        cprint(CONTAINER_RESOURCE_STRING.format(resource="CPU",
                                               used=stats['cpus_used'],
                                               allocated=stats['cpus_allocated'],
                                               unit="Cores",
                                               percentage=stats['cpus_utilization']))
    
    cprint(CONTAINER_RESOURCE_STRING.format(resource="Mem",
                                           used=stats['memory_used'] / 1024 / 1024,
                                           allocated=stats['memory_allocated'] / 1024 / 1024,
                                           unit="MB",
                                           percentage=stats['memory_utilization']))


if __name__ == '__main__':
    # Using this later.  For now, only a single argument (
    parser = argparse.ArgumentParser(description='Simple status script for DC/OS')

    parser.add_argument("-m", "--master",
                        help="Specify a master (defaults to the local hostname)")
    parser.add_argument("-l", "--long","-c","--containers",
                        help="Long output (will get info about containers)",
                        action="store_true", default=False)
    parser.add_argument("-r", "--print-reservations",
                        help="Break down reservations into individual reservations",
                        action="store_true", default=False)
    parser.add_argument("-C", "--container-csv",
                        help="Get container info, and print in csv form",
                        action="store_true", default=False)
    parser.add_argument("-a", "--get-apps",
                        help="Get Marathon app information (-aa for extra info)",
                        action="count", default=0)
    parser.add_argument("-n", "--get-network",
                        help="Get network information",
                        action="store_true", default=False)
    parser.add_argument("-i", "--show-inactive",
                        help="Show inactive Marathon apps",
                        action="store_true", default=False)
    parser.add_argument("-w", "--wait",
                        help="Specify time (in seconds, default 5) to wait between polls when measuring container CPU utilization",
                        default=5)
    parser.add_argument("-t", "--token-file")
    parser.add_argument("-s", "--save-token")
    parser.add_argument("--version",
                        action="store_true", default=False)


    args = parser.parse_args()

    if args.version:
        print("Version {}".format(VERSION))
        exit(0)
    # print(args)


    WAIT = int(args.wait)

    token = None
    if args.token_file:
        with open(args.token_file) as f:
            token = f.read().strip()

    # Spaghetti logic here.
    GET_CONTAINER_STATS = False
    # if len(sys.argv) > 1 and sys.argv[1] == '-l':
    if args.long:
        GET_CONTAINER_STATS = True
    
    if args.container_csv:
        CSV_MODE = True
        GET_CONTAINER_STATS = True

    RESERVATION_BREAKDOWN = False
    # if len(sys.argv) > 1 and sys.argv[1] == '-l':
    if args.print_reservations:
        RESERVATION_BREAKDOWN = True



    # This is all messy as hell.  Needs to be cleaned up.
    GET_MARATHON = args.get_apps
    SHOW_INACTIVE = args.show_inactive
    GET_NETWORK = args.get_network

    if GET_MARATHON and token == None:
        token = login(args.master)
        # token = get_auth_token(None, 'admin', 'thisismypassword') # Defaults for testing
        # print(token)

    if token and args.save_token:
        with open(args.save_token, 'w') as f:
            f.write(token)

    if GET_MARATHON > 0:
        apps, json_string = get_marathon_apps(args.master, token)
        print_marathon_apps(apps, GET_MARATHON, SHOW_INACTIVE)
    

    # exit(0)
    if GET_MARATHON == 0:
        try:
            slaves = get_slaves(args.master)
        except requests.exceptions.ConnectionError:
            if args.master == None:
                print("Nothing found listening locally on port 5050; specify a master hostname/IP address with -m option")
            elif args.master == "localhost":
                print("Masters don't listen on loopback; must use actual hostname/IP address")
            else:
                print("Unable to connect to master at http://{}:5050/".format(args.master))
                print("Note: script does not currently support https or strict mode")
            exit(1)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            exit(1)

        print_cluster_stats(slaves)

        print_agent_info(slaves['slaves'], GET_CONTAINER_STATS, RESERVATION_BREAKDOWN, wait=WAIT)

    if GET_NETWORK:
        try:
            state = get_state_json(args.master)
        except requests.exceptions.ConnectionError:
            if args.master == None:
                print("Nothing found listening locally on port 5050; specify a master hostname/IP address with -m option")
            elif args.master == "localhost":
                print("Masters don't listen on loopback; must use actual hostname/IP address")
            else:
                print("Unable to connect to master at http://{}:5050/".format(args.master))
                print("Note: script does not currently support https or strict mode")
            exit(1)
        except:
            print("Unexpected error:", sys.exc_info()[0])
            exit(1)

        print_minuteman(state)

    # print(GET_MARATHON)
