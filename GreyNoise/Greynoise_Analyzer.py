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
        level = "info"
        namespace = "GreyNoise"

        if raw.get('data'):
            for record in raw.get('data', []):
                classification = record.get('classification', 'unknown')
                last_seen = record.get('last_seen', None)
                tags = record.get('tags', None)
                if classification == 'malicious':
                    level = 'malicious'
                    score = "5"
                elif classification == 'benign':
                    level = 'safe'
                    score = "0"
                else:
                    level = 'info'
                    score = "1"
        else:
            taxonomies.append(self.build_taxonomy('info', 'GreyNoise', 'Records', 'None'))                  

        taxonomies.append(self.build_taxonomy(level,namespace,"Score",score))
        taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
        if score == "5":
           for tag in tags:
               taxonomies.append(self.build_taxonomy(level,namespace,"Tag",tag))

        return {'taxonomies': taxonomies}


if __name__ == '__main__':
    GreyNoiseAnalyzer().run()
