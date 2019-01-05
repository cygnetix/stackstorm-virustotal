from __future__ import print_function

import json

from virus_total_apis import PublicApi as VirusTotalPublicApi
from st2common.runners.base_action import Action

__all__ = [
    'FileReport'
]

class FileReport(Action):
    def run(self, resource):
        apikey = self.config['apikey']

        # https://developers.virustotal.com/v2.0/reference#file-report
        vt = VirusTotalPublicApi(apikey)
        response = vt.get_file_report(resource)
        
        # If VT has no record, we want to add results and totals fields
        if response.get('results').get('scan_id') == None:
            return (True, {"results": None})

        return (True, response)
