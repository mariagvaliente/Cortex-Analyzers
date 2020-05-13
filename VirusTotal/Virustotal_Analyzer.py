#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests
import json

class VirusTotalAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.key', None, 'VirusTotal API key is missing')
        self.basic_url = "https://www.virustotal.com/vtapi/v2/"


    def getReport(self):
        data = str(self.get_param('data', None, 'Data is missing'))
        if self.data_type == "hash":
            indicator_type = "file"
            # This is only for private api key
            params = {'apikey': self.api_key, 'resource': data, 'allinfo': 'true'}
            # For public api key
            #params = {'apikey': self.api_key, 'resource': data}
        elif self.data_type == "url":
            indicator_type = "url"
            # This is only for private api key
            params = {'apikey': self.api_key, 'resource': data, 'allinfo': 'true'}
            # For public api key
            #params = {'apikey': self.api_key, 'resource': data}
        elif self.data_type == "domain":
            indicator_type = "domain"
            params = {'apikey': self.api_key, 'domain': data}
        elif self.data_type == "ip":
            indicator_type = "ip-address"
            params = {'apikey': self.api_key, 'ip': data}
        else:
            self.error("Unknown data type")
        
        response_search = requests.get(self.basic_url + indicator_type + '/report', params=params)
        if response_search.status_code == 200:
            res_search_json = response_search.json()
            return res_search_json
        else:
            self.error("virustotal returns %s" % response.status_code)
        

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VT"
        predicate = "GetReport"
        value = "0"
        
        if self.service == "get":
            if self.data_type == "hash" or self.data_type == "url":
                if raw['scans'] != None:
                    value = "{}/{}".format(raw["positives"], raw["total"])
                    operation = int(raw["positives"])/int(raw["total"])
                    if raw["positives"] == 0:
                        level = "info"
                        score = "1"
                    elif raw["positives"] < 5:
                        level = "suspicious"
                        score = "3"
                    else:
                        if operation < 0.5:
                           level = "malicious"
                           score = "4"
                        else:
                           level = "malicious"
                           score = "5"
                if raw["first_seen"] != None:
                    first_seen = raw["first_seen"]
                    taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))
                if raw["last_seen"] != None:
                    last_seen = raw["last_seen"]
                    taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
            elif self.data_type == "domain" or self.data_type == "ip":
                if "resolutions" in raw:
                    value = "{} resolution(s)".format(len(raw["resolutions"]))
                    if len(raw["resolutions"]) == 0:
                        level = "info"
                        score = "1"
                    elif len(raw["resolutions"]) < 5:
                        level = "suspicious"
                        score = "3"
                    else:
                        level = "malicious"
                        score = "5"
                if "detected_urls" in raw:
                    value = "{} detected_url(s)".format(len(raw["detected_urls"]))
                    if len(raw["detected_urls"]) == 0:
                        level = "info"
                        score = "1"
                    elif len(raw["detected_urls"]) < 5:
                        level = "suspicious"
                        score = "3"
                    else:
                        level = "malicious"
                        score = "5"
                if "detected_downloaded_samples" in raw:
                    if len(raw["detected_downloaded_samples"]) == 0:
                        level = "info"
                        score = "1"
                    elif len(raw["detected_downloaded_samples"]) < 5:
                        level = "suspicious"
                        score = "3"
                    else:
                        level = "malicious"
                        score = "5"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))

        return {"taxonomies": taxonomies}

    def artifacts(self, report):
      artifacts = []
      if self.data_type == "domain" or self.data_type == "ip":
          detected_urls = report.get('detected_urls')
          detected_communicating_samples = report.get('detected_communicating_samples')
          detected_downloaded_samples = report.get('detected_downloaded_samples')
          detected_referrer_samples = report.get('detected_referrer_samples')
          resolutions = report.get('resolutions')
          if detected_urls != None:
             for detected_url in report.get('detected_urls'):
                 observable_url = {'dataType': 'url', 'data': detected_url['url']}
                 artifacts.append(observable_url)
          if detected_communicating_samples != None:
             for detected_communicating_sample in report.get('detected_communicating_samples'):
                 observable_communicating_hash = {'dataType': 'hash', 'data': detected_communicating_sample['sha256']}
                 artifacts.append(observable_communicating_hash)
          if detected_downloaded_samples != None:
             for detected_downloaded_sample in report.get('detected_downloaded_samples'):
                 observable_downloaded_hash = {'dataType': 'hash', 'data': detected_downloaded_sample['sha256']}
                 artifacts.append(observable_downloaded_hash)
          if detected_referrer_samples != None:
             for detected_referrer_sample in report.get('detected_referrer_samples'):
                 observable_referrer_hash = {'dataType': 'hash', 'data': detected_referrer_sample['sha256']}
                 artifacts.append(observable_referrer_hash)
          if resolutions != None:
             for resolution in report.get('resolutions'):
                 if self.data_type == 'ip':
                    observable_domain = {'dataType': 'domain', 'data': resolution['hostname']}
                    artifacts.append(observable_domain)
                 elif self.data_type == 'domain':
                    observable_ip = {'dataType': 'ip', 'data': resolution['ip_address']}
                    artifacts.append(observable_ip)
      else:
          additional_info = report.get('additional_info')
          contacted_domains = additional_info.get('contacted_domains')
          if contacted_domains != None:
              for d in contacted_domains:
                    observable_domain = {'dataType': 'domain', 'data': d}
                    artifacts.append(observable_domain)
          contacted_ips = additional_info.get('contacted_ips')
          if contacted_ips != None:
              for i in contacted_ips:
                    observable_ip = {'dataType': 'ip', 'data': i}
                    artifacts.append(observable_ip)

      return artifacts

    def run(self):
        if self.service == 'get':
            records = self.getReport()
            self.report(records)
        else:
            self.error('Invalid service')

if __name__ == '__main__':
    VirusTotalAnalyzer().run()