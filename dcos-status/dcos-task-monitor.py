#!/opt/mesosphere/bin/python
### Should point to python on a DC/OS master node.  Otherwise, relies on python3.5

import sys
sys.path.append('/opt/mesosphere/lib/python3.5/site-packages')

import argparse
import socket
import time
import requests
from collections import Counter

# Disable auth InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Hack to get working in proxy environment (basically ignores proxy)
session = requests.Session()
session.trust_env = False

'''.json() Doesn't actually return json - it's roughly equivalent to json.loads'''
def get_json(url):
    req = session.get(url)
    return req.json()

VERSION = 0.1

def get_state_json(hostname = None):
    if hostname is None:
        hostname = socket.gethostname()
    port = 5050

    url = "http://{hostname}:{port}/state.json".format(hostname=hostname, port=port)

    return get_json(url)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple task monitoring script for DC/OS')

    parser.add_argument("-m", "--master",
                        help="Specify a master (defaults to the local hostname)")
    parser.add_argument("-i", "--interval",
                        help="Specify time interval to search over (default 60)",
                        default=60)

    parser.add_argument("--version",
                        action="store_true", default=False)


    args = parser.parse_args()

    if args.version:
        print("Version {}".format(VERSION))
        exit(0)

    # try:
    interval = int(args.interval)
    ct = time.time()
    # print(ct)
    state = get_state_json(args.master)
    for framework in state['frameworks']:
        # print(framework)
        completed_tasks = framework['completed_tasks']
        recent = list(filter(lambda x: (ct - x['statuses'][-1]['timestamp']) < interval, completed_tasks))
        finished = list(filter(lambda x: x['statuses'][-1]['state'] == 'TASK_FINISHED', recent))
        failed = list(filter(lambda x: x['statuses'][-1]['state'] == 'TASK_FAILED', recent))

        
        if framework['name'] == 'marathon':
            finished_count = Counter([c['name'] for c in finished])
            failed_count = Counter([c['name'] for c in failed])
            apps = set(finished_count + failed_count)

            for app in apps:
                print("marathon[{}],{},{}".format(app, finished_count[app], failed_count[app]))
        else:
            # if len(finished) > 0 or len(failed) > 0:
            print("{},{},{}".format(framework['name'],len(finished),len(failed)))