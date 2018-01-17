#!/opt/mesosphere/bin/python3

# import sys
# sys.path.append('/opt/mesosphere/lib/python3.5/site-packages')

import sys
import os
import glob
import shutil
import pprint
import time


MESOS_DOCKER_STORE = "/var/lib/mesos/slave/store/docker/"
LINKS = "/var/lib/mesos/slave/provisioner/containers/*/backends/overlay/scratch/*/links/*"
POD_LINKS = "/var/lib/mesos/slave/provisioner/containers/*/containers/*/backends/overlay/scratch/*/links/*"
LAYER_DIRECTORY = "/var/lib/mesos/slave/store/docker/layers"
STAGING_DIRECTORY = "/var/lib/mesos/slave/store/docker/staging"
MIN_AGE = 3600 # Will not delete anything that has been touched in the past 60 minutes

clean = False

if len(sys.argv) > 1 and sys.argv[1] == "CLEAN":
  clean = True

# All layers currently in use
links = glob.glob(LINKS)
layers_in_use = [os.path.basename(os.path.dirname(os.readlink(link))) for link in links]
pod_links = glob.glob(POD_LINKS)
pod_layers_in_use = [os.path.basename(os.path.dirname(os.readlink(link))) for link in pod_links]

all_layers_in_use = layers_in_use + pod_layers_in_use

# print("Layers currently in use")
# print(len(layers_in_use))
# pprint.pprint(layers_in_use)

# All layers
try:
  layers = os.listdir(LAYER_DIRECTORY)
except OSError as e:
  print("No layer directory found at [{}].  \nUsually means no Mesos containers have been run on this box yet.  \nQuitting now.".format(LAYER_DIRECTORY))
  exit(0)
# pprint.pprint(layers)

# Current time
ctime = time.time()

# Look at all layers.  Any that are older than 60 minutes and not in use get deleted
for layer in layers:
  layer_path = LAYER_DIRECTORY + "/" + layer
  # print(layer_path)
  mtime = os.path.getmtime(layer_path)
  dtime = ctime - mtime
  if layer in all_layers_in_use:
    print("Layer [{}] currently in use.  Skipping.".format(layer))
  elif dtime < MIN_AGE:
    print("Layer [{}] is less than {} seconds old.  Skipping.".format(layer, MIN_AGE))
  else:
    print("Layer [{}] is not in use and greater than {} seconds old.  Deleting...".format(layer, MIN_AGE))
    print(layer_path)
    if clean:
      try:
        shutil.rmtree(layer_path)
        pass
      except e:
        print(e)
    else:
      print("Defaulting to no-change mode.  Add 'CLEAN' to your command line run to actually delete")

# Look at items in the staging directory
staging_layers = os.listdir(STAGING_DIRECTORY)
# pprint.pprint(staging_layers)

# Any layers in staging directory that are more than 60 minutes old get deleted
for layer in staging_layers:
  layer_path = STAGING_DIRECTORY + "/" + layer
  mtime = os.path.getmtime(layer_path)
  dtime = ctime - mtime
  if dtime < MIN_AGE:
    print("Staging item [{}] is less than {} seconds old.  Skipping.".format(layer,MIN_AGE))
  else:
    print("Staging item [{}] is greater than {} seconds old.  Deleting...".format(layer,MIN_AGE))
    print(layer_path)
    if clean:
      try:
        shutil.rmtree(layer_path)
        pass
      except e:
        print(e)
    else:
      print("Defaulting to no-change mode.  Add 'CLEAN' to your command line run to actually delete")

if not clean:
  print("Because of default no-change mode, no changes were made.  Add CLEAN to command line to actually make changes.  For example: \n    ./ucr-gc.py CLEAN")