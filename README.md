# VirusTotal Integration Pack

Intergration with the https://virustotal.com service. Currently it allows for file hashes to be submitted and the reputation of that file will be returned.

## Configuration

Copy the example configuration in [virustotal.yaml.example](./virustotal.yaml.example) to `/opt/stackstorm/configs/virustotal.yaml` and populated it with a valid apikey.

It should contain:

* ``apikey`` - An apikey obtained by signing up for an account on https://virustotal.com.

## Actions

* ``file_report`` - Retrieve file scan reports.
* ``url_report`` - Retrieve URL scan reports.
