# VirusTotal Integration Pack

Intergration with the https://virustotal.com service. Currently it allows for file hashes to be submitted and the reputation of that file will be returned.

## Configuration

Copy the example configuration in [virustotal.yaml.example](./virustotal.yaml.example) to `/opt/stackstorm/configs/virustotal.yaml` and populated it with a valid apikey.

It should contain:

* ``apikey`` - An apikey obtained by signing up for an account on https://virustotal.com.

## Actions

* ``file_report`` - Retrieve file scan reports.
* ``url_report`` - Retrieve URL scan reports.

## References

The names of actions used in this integration pack follow the naming convention used by VirusTotal's API. Refer to VT's API documentation for a better understanding of how to use this pack.
* https://developers.virustotal.com/v2.0/reference
