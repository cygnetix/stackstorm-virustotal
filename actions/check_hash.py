from __future__ import print_function

import json

from virus_total_apis import PublicApi as VirusTotalPublicApi
from st2common.runners.base_action import Action

class CheckHash(Action):
    def run(self, file_hash):
        api_key = self.config['api_key']
        
        vt = VirusTotalPublicApi(api_key)
        response = vt.get_file_report(file_hash)
        
        # if VT has no record, we want to add results and totals fields
        if response.get('results').get('scan_id') == None:
            return (True, {"results": None})

        return (True, response)
