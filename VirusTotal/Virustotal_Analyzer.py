#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests
import json

class VirusTotalAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
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
        # default values
        level = "info"
        namespace = "VT"
        predicate = "GetReport"
        value = "0"
        
        if self.data_type == "hash" or self.data_type == "url":
           if raw['scans'] != None:
              value = "{}/{}".format(raw["positives"], raw["total"])
              operation = int(raw["positives"])/int(raw["total"])
              if raw["positives"] == 0:
                 level = "safe"
                 score = "0"
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
              taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
              taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))
              if raw["first_seen"] != None:
                 first_seen = raw["first_seen"]
                 taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))
              if raw["scan_date"] != None:
                 last_seen = raw["scan_date"]
                 taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
              if self.data_type == 'hash':
                 if raw['tags'] != None:
                    if len(raw["tags"]) != 0:
                       for tag in raw["tags"]:
                           taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))
        elif self.data_type == "domain" or self.data_type == "ip":
              if "resolutions" in raw:
                  value = "{} resolution(s)".format(len(raw["resolutions"]))
                  taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
              if "detected_urls" in raw:
                  value = "{} detected_url(s)".format(len(raw["detected_urls"]))
                  taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
              if "detected_downloaded_samples" in raw:
                  value = "{} detected_downloaded_sample(s)".format(len(raw["detected_downloaded_samples"]))
                  taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
              if "country" in raw:
                 taxonomies.append(self.build_taxonomy(level, namespace, "Country", raw['country']))

        return {"taxonomies": taxonomies}

    def artifacts(self, report):
      artifacts = []
      if self.data_type == "domain" or self.data_type == "ip":
          detected_urls = report.get('detected_urls')
          detected_communicating_samples = report.get('detected_communicating_samples')
          detected_downloaded_samples = report.get('detected_downloaded_samples')
          detected_referrer_samples = report.get('detected_referrer_samples')
          resolutions = report.get('resolutions')
          domain_siblings = report.get('domain_siblings')
          if detected_urls != None:
             for detected_url in report.get('detected_urls'):
                 observable_url = {'dataType': 'url', 'data': detected_url['url']}
                 if observable_url not in artifacts:
                    artifacts.append(observable_url)
          if detected_communicating_samples != None:
             for detected_communicating_sample in report.get('detected_communicating_samples'):
                 observable_communicating_hash = {'dataType': 'hash', 'data': detected_communicating_sample['sha256']}
                 if observable_communicating_hash not in artifacts:
                    artifacts.append(observable_communicating_hash)
          if detected_downloaded_samples != None:
             for detected_downloaded_sample in report.get('detected_downloaded_samples'):
                 observable_downloaded_hash = {'dataType': 'hash', 'data': detected_downloaded_sample['sha256']}
                 if observable_downloaded_hash not in artifacts:
                    artifacts.append(observable_downloaded_hash)
          if detected_referrer_samples != None:
             for detected_referrer_sample in report.get('detected_referrer_samples'):
                 observable_referrer_hash = {'dataType': 'hash', 'data': detected_referrer_sample['sha256']}
                 if observable_referrer_hash not in artifacts:
                    artifacts.append(observable_referrer_hash)
          if resolutions != None:
             for resolution in report.get('resolutions'):
                 if self.data_type == 'ip':
                    observable_domain = {'dataType': 'domain', 'data': resolution['hostname']}
                    if observable_domain not in artifacts:
                       artifacts.append(observable_domain)
                 elif self.data_type == 'domain':
                    observable_ip = {'dataType': 'ip', 'data': resolution['ip_address']}
                    if observable_ip not in artifacts:
                       artifacts.append(observable_ip)
          if domain_siblings != None:
             for domain in report.get('domain_siblings'):
                 observable_domain = {'dataType': 'domain', 'data': domain}
                 if observable_domain not in artifacts:
                    artifacts.append(observable_domain)                 
      else:
          additional_info = report.get('additional_info')
          if additional_info != None:
              contacted_domains = additional_info.get('contacted_domains')
              if contacted_domains != None:
                  for d in contacted_domains:
                        observable_domain = {'dataType': 'domain', 'data': d}
                        if observable_domain not in artifacts:
                           artifacts.append(observable_domain)
              contacted_ips = additional_info.get('contacted_ips')
              if contacted_ips != None:
                  for i in contacted_ips:
                        observable_ip = {'dataType': 'ip', 'data': i}
                        if observable_ip not in artifacts:
                           artifacts.append(observable_ip)
              content_hash = additional_info.get('Response content SHA-256')
              if content_hash != None:
                 observable_hash = {'dataType': 'hash', 'data': content_hash}
                 if observable_hash not in artifacts:
                    artifacts.append(observable_hash)
          if self.data_type == 'hash':
             submission_names = report.get('submission_names')
             if submission_names != None:
                if len(submission_names) != 0:
                   for s in submission_names:
                       observable_filename = {'dataType': 'filename', 'data': s}
                       if observable_filename not in artifacts:
                          artifacts.append(observable_filename)
             contacted_urls = report.get('ITW_urls')
             if contacted_urls != None:
                if len(contacted_urls) != 0:
                   for url in contacted_urls:
                       observable_url = {'dataType': 'url', 'data': url}
                       if observable_url not in artifacts:
                          artifacts.append(observable_url)             
          

      return artifacts

    def run(self):
        try:
            records = self.getReport()
            self.report(records)
            
        except Exception as e: 
            print(e)
            self.unexpectedError("Unknown error while running VirusTotal analyzer")
            
if __name__ == '__main__':
    VirusTotalAnalyzer().run()