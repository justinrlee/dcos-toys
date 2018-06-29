# Nginx container with Splunk Universal Forwarder

This is a demo container that runs nginx and has the Splunk Universal Forwarder embedded.

Here's how it works:

1. The Dockerfile installs wget and downloads Splunk Universal Forwarder tarball (and a handful of other utilities that are nice for a test container)
1. The Universal Forwarder gets extracted to /opt/splunkforwarder
1. A seed file gets placed that creates a local admin:password user (this is only for the forwarder)
1. The entrypoint starts the forwarder
1. If the env variable SPLUNK_SERVER is set (for example, to 192.168.10.27:9997), it will be added as an endpoint to forward to
1. If the env variable SPLUNK_LOG_DIRECTORIES is set (supports semicolon delimiters; for example, if set to '/var/log/nginx;/var/log/something'), it will make those directories if they don't already exist and start monitoring them with Splunk
1. It will then run whatever command is in the Docker CMD field.

Sample usage:

```bash
docker run -d -e SPLUNK_SERVER=192.168.10.27:9997 -e SPLUNK_LOG_DIRECTORIES="/var/log/nginx;/var/log/other" nginx/justinrlee:splunk
```

```json
{
  "id": "/nginx-splunk",
  "cpus": 1.0,
  "mem": 128,
  "instances": 1,
  "container": {
    "portMappings": [
      {
        "containerPort": 80,
        "hostPort": 0,
        "protocol": "tcp",
      }
    ],
    "type": "DOCKER",
    "docker": {
      "image": "justinrlee/nginx:splunk"
    }
  },
  "env": {
    "SPLUNK_SERVER": "192.168.10.27:9997",
    "SPLUNK_LOG_DIRECTORIES": "/var/log/nginx"
  },
  "networks": [
    {
      "mode": "container/bridge"
    }
  ]
}
```
