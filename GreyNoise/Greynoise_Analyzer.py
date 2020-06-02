#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class GreyNoiseAnalyzer(Analyzer):

    def run(self):

        if self.data_type == "ip":
            api_key = self.get_param('config.key', None)
            url = 'https://api.greynoise.io/v2/experimental/gnql?query=ip:%s' % self.get_data()

            if api_key:
                headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Key': '%s' % api_key }
            else:
                headers = {'Content-Type': 'application/x-www-form-urlencoded' }

            response = requests.get(url, headers=headers)
            if not (200 <= response.status_code < 300):
                self.error('Unable to query GreyNoise API\n{}'.format(response.text))
            self.report(response.json())

        else:
            self.notSupported()

    def summary(self, raw):
        taxonomies = []
        namespace = "GreyNoise"

        if raw.get('data'):
            for record in raw.get('data', []):
                classification = record.get('classification', 'unknown')
                first_seen = record.get('first_seen', None)
                last_seen = record.get('last_seen', None)
                tags = record.get('tags', None)
                if classification == 'malicious':
                    level = 'malicious'
                    score = "4"
                elif classification == 'unknown':
                    level = 'info'
                    score = "1"
                else:
                    level = 'safe'
                    score = "0"
                    
                taxonomies.append(self.build_taxonomy(level,namespace,"Score",score))
                
                if first_seen != None:
                   taxonomies.append(self.build_taxonomy(level,namespace,"First_seen",first_seen))
                if last_seen != None:
                   taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
                if len(tags) != 0:
                   for tag in tags:
                       taxonomies.append(self.build_taxonomy(level,namespace,"Tag",tag))
                country = record.get('metadata').get('country', None)
                city = record.get('metadata').get('city', None)
                if country != None:
                   taxonomies.append(self.build_taxonomy(level,namespace,"Country",country))
                if city != None:
                   taxonomies.append(self.build_taxonomy(level,namespace,"City",city))
                
        else:
            taxonomies.append(self.build_taxonomy('info', 'GreyNoise', 'Records', 'None'))                  

        


        return {'taxonomies': taxonomies}
        
    def artifacts(self, report):
        artifacts = []
        if report.get('data'):
            for record in report.get('data'):
                if record['metadata']['rdns'] != "" and record['metadata']['rdns'] != None:
                   observable_domain = {'dataType': 'domain', 'data': record['metadata']['rdns']}
                   if observable_domain not in artifacts:
                      artifacts.append(observable_domain)
              
        return artifacts


if __name__ == '__main__':
    GreyNoiseAnalyzer().run()
