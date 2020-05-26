#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import requests
import datetime
import json
from dateutil.parser import parse
#List for collecting dates of each result
dates = []
#List for collecting contacted urls of each result
urls = []

class UrlscanAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'Service parameter is missing')
        self.api_key = self.get_param('config.key', None, 'Missing URLScan API key')
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"}

    def get_search(self):
        data = self.getData()
        indicator_value = str(data)
        indicator_type = str(self.data_type)
        if indicator_type == "url":
            indicator_value_parsed_hxxp = indicator_value.replace("hxxp", "http")
            response = requests.get('https://urlscan.io/api/v1/search?q="{}"'.format(indicator_value_parsed_hxxp),headers=self.headers)
        else:
            response = requests.get('https://urlscan.io/api/v1/search?q={}:{}'.format(indicator_type, indicator_value),headers=self.headers)
        if response.status_code == 200:
            if self.data_type == "url":
                response_json = response.json()
                response_results = response_json.get('results')
                if len(response_results) == 0:
                    self.error("Unknown sample in Urlscan.io")
                else:
                    id_url = response_results[0].get('_id')
                    url_api_search = "https://urlscan.io/api/v1/result/"
                    response_search = requests.get(url_api_search + str(id_url), headers=self.headers)
                    res_search_json = response_search.json()
                    return res_search_json
            else:
                response_json = response.json()
                response_results = response_json.get('results')
                if len(response_results) == 0:
                    self.error("Unknown sample in Urlscan.io")
                else:
                    for r in response_results:
                        task = r.get('task')
                        time = task.get('time')
                        dates.append(time)
                        url = task.get('url')
                        if url not in urls:
                           urls.append(url)
                return response_json
        else:
            self.error("urlscan.io returns %s" % response.status_code)
            
        
    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Urlscan.io"
        
        if self.data_type == "url":
            malicious = raw["verdicts"]["overall"]["malicious"]
            score = raw["verdicts"]["overall"]["score"]
            votesBenign = raw["verdicts"]["community"]["votesBenign"]
            tags = raw["verdicts"]["overall"]["tags"]
            #TAGS
            if len(tags) != 0:
               for tag in tags:
                   taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))        
            #SCORE
            if malicious:
               level = 'malicious'
            elif score > 0:
               level = 'suspicious'
            if score == None:
               my_score == '1'
               level = 'info'
            else:
               if int(score) == 0:
                  if int(votesBenign) > 0:
                     my_score = '0'
                     level = 'safe'
                  else:
                     my_score = '1'
                     level = 'info'
               elif 20 > int(score) >= 1:
                  my_score = '2'
               elif 60 > int(score) >= 20:
                  my_score = '3'
               elif 80 > int(score) >= 60:
                  my_score = '4'
               elif 100 >= int(score) >= 80:
                  my_score = '5'
        else:
            total = raw['total']
            if total <= 1:
               my_score = '1'
               level = 'info'
            else:
               my_score = '3'
               level = 'suspicious'
            #FIRST AND LAST SEEN
            if len(dates) != 0:
               first_seen = dates[-1]
               taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))
               last_seen = dates[0]
               taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
               
        taxonomies.append(self.build_taxonomy(level, namespace, "Score", my_score))
        return {"taxonomies": taxonomies}

    def artifacts(self, report):
        artifacts = []
        if self.data_type == "url":
            if report.get('lists') != None:
               ips = report.get('lists').get('ips')
               hashes = report.get('lists').get('hashes')
               domains = report.get('lists').get('domains')
               if len(ips) != 0:
                  for ip in ips:
                      observable_ip = {'dataType': 'ip', 'data': ip}
                      if observable_ip not in artifacts:
                         artifacts.append(observable_ip)
               if len(domains) != 0:
                  for domain in domains:
                      observable_domain = {'dataType': 'domain', 'data': domain}
                      if observable_domain not in artifacts:
                         artifacts.append(observable_domain)
               if len(hashes) != 0:
                  for hash in hashes:
                      observable_hash = {'dataType': 'hash', 'data': hash}
                      if observable_hash not in artifacts:
                         artifacts.append(observable_hash)
        else:
            if len(urls) != 0:
               for url in urls:
                  observable_url = {'dataType': 'url', 'data': url}
                  if observable_url not in artifacts:
                      artifacts.append(observable_url)
                      
        return artifacts


    def run(self):
        try:
            if self.service == "search_ioc":
               records = self.get_search()
               self.report(records)
            else:
               self.error('Invalid service')        
            
        except Exception as e: 
            print(e)
            self.unexpectedError("Unknown error while running Urlscan analyzer")



if __name__ == '__main__':
    UrlscanAnalyzer().run()