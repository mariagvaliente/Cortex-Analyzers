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
        self.api_key = self.get_param('config.key', None, 'Missing URLScan API key')
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"}

    def get_search(self):
        data = self.getData()
        indicator_value = str(data)
        indicator_type = str(self.data_type)
        if indicator_type == "url":
            indicator_value_parsed = indicator_value.replace("hxxp", "http")
            response = requests.get('https://urlscan.io/api/v1/search?q="{}"'.format(indicator_value_parsed),headers=self.headers)
        else:
            response = requests.get('https://urlscan.io/api/v1/search?q={}:{}'.format(indicator_type, indicator_value),headers=self.headers)

        if response.status_code == 200:
            if self.data_type == "url":
                response_json = response.json()
                response_results = response_json.get('results')
                if len(response_results) == 0:
                    return ({'page': 'Not found'})
                else:
                    id_url = response_results[0].get('_id')
                    url_api_search = "https://urlscan.io/api/v1/result/"
                    response_search = requests.get(url_api_search + str(id_url), headers=self.headers)
                    res_search_json = response_search.json()
                    return res_search_json
            else:
                response_json = response.json()
                offset = 0

                total_results = response_json['total']
                response_results = response_json.get('results')

                if len(response_results) == 0:
                    return ({'results': [], 'total': 0})

                else:
                    for r in response_results:
                        task = r.get('task')
                        time = task.get('time')
                        dates.append(time)
                        url = task.get('url')
                        if url not in urls:
                            urls.append(url)

                    offset += len(response_results)

                    if total_results <= 10000:
                        while(offset < total_results):
    
                            response = requests.get(
                                'https://urlscan.io/api/v1/search?q={}:{}&offset={}'.format(indicator_type, indicator_value, offset),
                                headers=self.headers)
                            response_results = response.json()['results']
                            
                            for r in response_results:
                                task = r.get('task')
                                time = task.get('time')
                                dates.append(time)
                                url = task.get('url')
                                if url not in urls:
                                   urls.append(url)
    
                            offset += len(response_results)

                    return response_json
                    
        elif response.status_code == 400:
             return ({'page': 'Not found'})
        else:
            self.error("urlscan.io returns %s" % response.status_code)
            
        
    def summary(self, raw):
        taxonomies = []
        namespace = "Urlscan.io"
        level = "info"
        print("ENTRA")
        if self.data_type == "url":
            malicious = raw["verdicts"]["overall"]["malicious"]
            score = raw["verdicts"]["overall"]["score"]
            votesBenign = raw["verdicts"]["community"]["votesBenign"]
            tags = raw["verdicts"]["overall"]["tags"]
       
            #SCORE
            if malicious:
               level = 'malicious'
            elif score > 0:
               level = 'suspicious'
            
            if int(score) == 0:
               my_score = '0'
               level = 'safe'
            elif 20 > int(score) >= 1:
               my_score = '2'
            elif 60 > int(score) >= 20:
               my_score = '3'
            elif 80 > int(score) >= 60:
               my_score = '4'
            elif 100 >= int(score) >= 80:
               my_score = '5'
            else:
               my_score = '1'
                  
            taxonomies.append(self.build_taxonomy(level, namespace, "Score", my_score))
            
            #TAGS
            if len(tags) != 0:
               for tag in tags:
                   taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag)) 
            
            # LAST SEEN
            requests = raw["data"]["requests"]
            if len(requests) != 0:
               last_seen_timestamp = requests[0].get('request').get('wallTime')
               last_seen = datetime.datetime.fromtimestamp(last_seen_timestamp).isoformat()
               taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
        else:
            #FIRST AND LAST SEEN
            if len(dates) != 0:
               first_seen = dates[-1]
               taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))
               last_seen = dates[0]
               taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
               
        
        print(taxonomies)
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
                      
        print(artifacts)
        return artifacts


    def run(self):
        try:
            records = self.get_search()
            self.report(records)     
            
        except Exception as e: 
            print(e)
            self.unexpectedError("Unknown error while running Urlscan analyzer")



if __name__ == '__main__':
    UrlscanAnalyzer().run()