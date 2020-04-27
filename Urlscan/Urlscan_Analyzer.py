#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import requests
import datetime
from dateutil.parser import parse

class UrlscanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'Missing URLScan API key')
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        self.basic_url = "https://urlscan.io/api/v1/result/"

    def get_scan(self):
        data = self.getData()
        indicator_value = str(data)
        response = requests.get('https://urlscan.io/api/v1/search?q=domain:{}'.format(indicator_value),headers=self.headers)
        if response.status_code == 200:
            response_json = response.json()
            response_results = response_json.get('results')
            #ID Scan
            id_url = response_results[0].get('_id')
            return id_url
        else:
            self.error("urlscan.io returns %s" % response.status_code)

    def get_results(self):
        id_url = self.get_scan()
        url_api_search = str(self.basic_url)
        response_search = requests.get(url_api_search + str(id_url), headers=self.headers)
        res_search_json = response_search.json()
        return res_search_json


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Urlscan.io"

        malicious = raw["verdicts"]["overall"]["malicious"]
        score = raw["verdicts"]["overall"]["score"]
        votesBenign = raw["verdicts"]["community"]["votesBenign"]
        tags = raw["verdicts"]["overall"]["tags"]
        dates = []
        data = raw.get('data')
        requests = data.get('requests')
        for request in requests:
            response = request.get('response')
            response_final = response.get('response')
            headers = response_final.get('headers')
            if headers != None:
               last_seen = headers.get('Last-Modified')
               if last_seen != None:
                  last_seen_parsed = parse(last_seen).isoformat()
                  dates.append(last_seen_parsed)
            else:
               date = "Not found"
        if len(dates) != 0:
           dates_sort = sorted(dates)
           date = dates_sort[-1]
        else:
           date = "Not found"

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

        if len(tags) != 0:
           for tag in tags:
               taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))
        taxonomies.append(self.build_taxonomy(level, namespace, "Score", my_score))
        taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", date))
        return {"taxonomies": taxonomies}

    def artifacts(self, report):
        artifacts = []
        if report.get('lists') != None:
           ips = report.get('lists').get('ips')
           domains = report.get('lists').get('domains')
           hashes = report.get('lists').get('hashes')
           if len(ips) != 0:
              for ip in ips:
                  observable_ip = {'dataType': 'ip', 'data': ip}
                  artifacts.append(observable_ip)
           if len(domains) != 0:
              for domain in domains:
                  observable_domain = {'dataType': 'domain', 'data': domain}
                  artifacts.append(observable_domain)
           if len(hashes) != 0:
              for hash in hashes:
                  observable_hash = {'dataType': 'hash', 'data': hash}
                  artifacts.append(observable_hash)

        return artifacts


    def run(self):
        try:
            records = self.get_results()
            self.report(records)

        except Exception: # Unknown error
            self.unexpectedError("Unknown error while running Urlscan analyzer")



if __name__ == '__main__':
    UrlscanAnalyzer().run()