# Virus Total Integration Pack

Intergration with the https://virustotal.com service. Currently it allows for file hashes to be submitted and the reputation of that file will be returned.

## Configuration

Copy the example configuration in [virustotal.yaml.example](./virustotal.yaml.example) to `/opt/stackstorm/configs/virustotal.yaml` and populated it with a valid apikey.

It should contain:

* ``apikey`` - An apikey obtained by signing up for an account on https://urlscan.io.
* ``verify`` - Determines if SSL is validated (defautls to on)

## Actions

* ``file_hash`` - Submits a file hash (md5, sha1, sha256 etc) to the virustotal.com API and returns that file's reputation, if known.
