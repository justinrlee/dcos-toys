#!/usr/bin/python
import copy
import time

def print_list(x):
    for c, v in enumerate(x):
        print(str(c + 1) + ": " + v)

old_input = raw_input("Enter a comma-separated list of old master IPs: ")
new_input = raw_input("Enter a comma-separated list of new master IPs: ")

old = [ x.strip() for x in old_input.split(",") ]
new = [ x.strip() for x in new_input.split(",") ]

if len(old) != len(new):
    print("Length of two lists does not match")

old.sort()
new.sort()

print("ZK Order for old masters:")
print_list(old)

print("ZK Order for new masters:")
print_list(new)

print("")

current = copy.copy(old)
master_order = []
replace_list = []

while current != new:
    for i in range(len(old)):
        if current[i] != new[i]:
            temp = copy.copy(current)
            temp[i] = new[i]
            if temp == sorted(temp):
                master_order.append((i+1))
                r = "[" + old[i] + "] -> [" + new[i] + "]"
                replace_list.append(r)
                current = copy.copy(temp)
                
                print("Replace Master " + str(i + 1) + " " + r + ":")
                print_list(current)
                break

print("Replace masters in this order: " + str(master_order))
print_list(replace_list)