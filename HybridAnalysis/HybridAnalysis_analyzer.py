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

        return {"taxonomies": taxonomies}

    def artifacts(self, report):
        artifacts = []
        vx = report.get('vx_family')
        if vx != None:
           if vx.find('CVE') >= 0:
              observable_vx = {'dataType': 'vulnerability', 'data': vx}
           else:
              observable_vx = {'dataType': 'malware-family', 'data': vx}
           artifacts.append(observable_vx)
        mitre_attcks = report.get('mitre_attcks')
        if len(mitre_attcks) != 0:
           for attack in mitre_attcks:
               technique = attack.get('technique')
               observable_mittre = {'dataType': 'attack_pattern', 'data': technique}
               artifacts.append(observable_mittre)
        compromised_hosts = report.get('compromised_hosts')
        if len(compromised_hosts) != 0:
           for host in compromised_hosts:
               observable_compromised_hosts = {'dataType': 'ip', 'data': host}
               artifacts.append(observable_compromised_hosts)
        hosts = report.get('hosts')
        if len(hosts) != 0:
           for host in hosts:
               observable_hosts = {'dataType': 'ip', 'data': host}
               artifacts.append(observable_hosts)
        domains = report.get('domains')
        if len(domains) != 0:
           for domain in domains:
               observable_domains = {'dataType': 'domain', 'data': domain}
               artifacts.append(observable_domains)
        extracted_files = report.get('extracted_files')
        if len(extracted_files) != 0:
           for file in extracted_files:
               file_name = file.get('name')
               observable_files = {'dataType': 'filename', 'data': file_name}
               artifacts.append(observable_files)

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

            url = str(self.basic_url) + str(query_url)

            response = requests.post(url, data=self.data, headers=self.headers)
            res_search = response.json()

            if indicator_type == 'hash':
                self.report(res_search[0])
            else:
                url_report = 'https://www.hybrid-analysis.com/api/v2/report/'
                query = '/summary'
                result = res_search.get('result')
                job_id = result[0].get('job_id')
                url = url_report + str(job_id) + query
                response_analysis = requests.get(url, headers = self.headers)
                res_analysis =response_analysis.json()
                self.report(res_analysis)

        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HybridAnalysisAnalyzer().run()