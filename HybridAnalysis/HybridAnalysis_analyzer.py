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
        dates = []
        verdict = raw.get('verdict')
        threat_score = raw.get('threat_score')
        submissions = raw.get('submissions')
        tags = raw.get('tags')
        av_detect = raw.get('av_detect')
        # default value
        namespace = "HybridAnalysis"
        
        # SCORE
        if verdict == 'malicious':
           level = 'malicious'
        elif verdict == 'suspicious':
           level = 'suspicious'
        elif verdict == 'whitelisted':
           level = 'safe'
        else:
           level = 'info'
        if threat_score == None:
           if av_detect != None:
              if 20 > int(av_detect) >= 0:
                 score = '2'
                 level = 'info'
              elif 60 > int(av_detect) >= 20:
                 score = '3'
                 level = 'suspicious'
              elif 80 > int(av_detect) >= 60:
                 score = '4'
                 level = 'malicious'
              elif 100 >= int(av_detect) >= 80:
                 score = '5'
                 level = 'malicious'
           else:
              score = '0'
              level = 'safe'
        else:
           if threat_score == '0':
              score = '0'
           elif 20 > int(threat_score) >= 1:
              score = '2'
           elif 60 > int(threat_score) >= 20:
              score = '3'
           elif 80 > int(threat_score) >= 60:
              score = '4'
           elif 100 >= int(threat_score) >= 80:
              score = '5'
        taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))
        
        # FIRST AND LAST SEEN
        for submission in submissions:
              dates.append(submission['created_at'])
        if len(dates) != 0:
           dates_sort = sorted(dates)
           first_seen = dates_sort[0]
           last_seen = dates_sort[-1]
           if first_seen != None:
             taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))         
           if last_seen != None:
             taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))              
              
        # TAGS
        if len(tags) != 0:
           for tag in tags:
               taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))
        return {"taxonomies": taxonomies}

    def artifacts(self, report):
        artifacts = []
        if report.get('count') != 0:
           vx = report.get('vx_family')
           if vx != None:
              if vx.find('CVE') >= 0:
                 observable_vx = {'dataType': 'vulnerability', 'data': vx}
              else:
                 observable_vx = {'dataType': 'malware-family', 'data': vx}
              if observable_vx not in artifacts:
                 artifacts.append(observable_vx)
           mitre_attcks = report.get('mitre_attcks')
           if len(mitre_attcks) != 0:
              for attack in mitre_attcks:
                  technique = attack.get('technique')
                  observable_mittre = {'dataType': 'attack_pattern', 'data': technique}
                  if observable_mittre not in artifacts:
                     artifacts.append(observable_mittre)
           compromised_hosts = report.get('compromised_hosts')
           if len(compromised_hosts) != 0:
              for host in compromised_hosts:
                  observable_compromised_hosts = {'dataType': 'ip', 'data': host}
                  if observable_compromised_hosts not in artifacts:
                     artifacts.append(observable_compromised_hosts)
           hosts = report.get('hosts')
           if len(hosts) != 0:
              for host in hosts:
                  observable_hosts = {'dataType': 'ip', 'data': host}
                  if observable_hosts not in artifacts:
                     artifacts.append(observable_hosts)
           domains = report.get('domains')
           if len(domains) != 0:
              for domain in domains:
                  observable_domains = {'dataType': 'domain', 'data': domain}
                  if observable_domains not in artifacts:
                     artifacts.append(observable_domains)
           extracted_files = report.get('extracted_files')
           if len(extracted_files) != 0:
              for file in extracted_files:
                  file_name = file.get('name')
                  hash_sha1 = file.get('sha1')
                  hash_sha256 = file.get('sha256')
                  hash_md5 = file.get('md5')
                  observable_files = {'dataType': 'filename', 'data': file_name}
                  observable_hash_sha1 = {'dataType': 'hash', 'data': hash_sha1}
                  observable_hash_sha256 = {'dataType': 'hash', 'data': hash_sha256}
                  observable_hash_md5 = {'dataType': 'hash', 'data': hash_md5}
                  if observable_files not in artifacts:
                     artifacts.append(observable_files)
                  if observable_hash_sha1 not in artifacts:
                     artifacts.append(observable_hash_sha1)
                  if observable_hash_sha256 not in artifacts:
                     artifacts.append(observable_hash_sha256)
                  if observable_hash_md5 not in artifacts:
                     artifacts.append(observable_hash_md5)
           submit_name = report.get('submit_name')
           if submit_name != None:
              observable_filename = {'dataType': 'filename', 'data': submit_name}
              if observable_filename not in artifacts:
                 artifacts.append(observable_filename)
           md5 = report.get('md5')
           if md5 != None:
              observable_md5 = {'dataType': 'hash', 'data': md5}
              if observable_md5 not in artifacts:
                 artifacts.append(observable_md5)
           sha1 = report.get('sha1')
           if sha1 != None:
              observable_sha1 = {'dataType': 'hash', 'data': sha1}
              if observable_sha1 not in artifacts:
                 artifacts.append(observable_sha1)          
           sha256 = report.get('sha256')
           if sha256 != None:
              observable_sha256 = {'dataType': 'hash', 'data': sha256}
              if observable_sha256 not in artifacts:
                 artifacts.append(observable_sha256)
              
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
                if len(res_search) != 0:
                   self.report(res_search[0])
                else:
                   self.report({"search_terms": [{"id": "hash", "value": indicator_value}], "count": 0, "result": []})
            else:
                url_report = 'https://www.hybrid-analysis.com/api/v2/report/'
                query = '/summary'
                result = res_search.get('result')
                if len(result) != 0:
                   job_id = result[0].get('job_id')
                   url = url_report + str(job_id) + query
                   response_analysis = requests.get(url, headers = self.headers)
                   res_analysis =response_analysis.json()
                   self.report(res_analysis)
                else:
                   self.report(res_search)

        except ValueError as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    HybridAnalysisAnalyzer().run()