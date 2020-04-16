#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import requests
import time

from cortexutils.analyzer import Analyzer


class HybridAnalysisAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'Falcon Sandbox API key is missing')

        self.basic_url = 'https://www.hybrid-analysis.com/api/v2/search/'
        self.headers = {'api-key': self.api_key,'user-agent':'Falcon Sandbox'}


    def summary(self, raw):
        taxonomies = []

        # default values
        level = "info"
        namespace = "HybridAnalysis"

        if self.data_type in ['hash']:
            verdict = raw.get('verdict')
            threat_score = raw.get('threat_score')
            last_seen = raw.get('analysis_start_time')
            tags = raw.get('tags')

            if verdict == 'malicious':
                level = 'malicious'
            elif verdict == 'suspicious':
                level = 'suspicious'
            elif verdict == 'whitelisted':
                level = 'safe'
            else:
                level = 'info'
            if threat_score == None:
                threat_score = 'Not found'
            if last_seen == None:
                last_seen = 'Not found'

            if len(tags) != 0:
                for tag in tags:
                   taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))
            taxonomies.append(self.build_taxonomy(level, namespace, "Score", threat_score))
            taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
        else:
            count = raw.get('count')
            if count == 0:
               taxonomies.append(self.build_taxonomy(level, namespace, "Report", "Not found"))
            else:
               result = raw.get('result')
               verdict = result[0].get('verdict')
               threat_score = result[0].get('threat_score')
               last_seen = result[0].get('analysis_start_time')

               if verdict == 'malicious':
                  level = 'malicious'
               elif verdict == 'suspicious':
                  level = 'suspicious'
               elif verdict == 'whitelisted':
                  level = 'safe'
               else:
                  level = 'info'

               taxonomies.append(self.build_taxonomy(level, namespace, "Score", threat_score))
               taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))

        return {"taxonomies": taxonomies}

    def artifacts(self, report):
        artifacts = []
        if self.data_type in ['hash']:
            malware_family = report.get('vx_family')
            if malware_family != None:
               observable = {'dataType': 'malware_family', 'data': malware_family}
               artifacts.append(observable)
        else:
            count = report.get('count')
            if count != 0:
               result = report.get('result')
               malware_family = result[0].get('vx_family')
               observable = {'dataType': 'malware_family', 'data': malware_family}
               artifacts.append(observable)

        return artifacts

    def run(self):

        try:
            if self.data_type == 'hash':
                query_url = 'hash'
                query_data = self.get_param('data', None, 'Hash is missing')

            elif self.data_type == 'ip':
                query_url = 'terms'
                query_data = self.get_param('data', None, 'IP is missing')

            else:
                query_url = 'terms'
                query_data = self.get_param('data', None, 'Domain is missing')

            indicator_type = str(self.data_type)
            if str(self.data_type) == 'ip':
                indicator_type = 'host'
            indicator_value = str(query_data)
            self.data = {indicator_type: indicator_value}
            print(self.data)
            print(self.headers)

            url = str(self.basic_url) + str(query_url)

            r = requests.post(url, data=self.data, headers=self.headers)
            res_search = r.json()
            print(res_search)
            print(r)
            if indicator_type == 'hash':
                self.report(res_search[0])
            else:
                self.report(res_search)

        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HybridAnalysisAnalyzer().run()