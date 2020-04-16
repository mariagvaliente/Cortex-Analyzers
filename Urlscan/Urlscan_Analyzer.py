#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import requests

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

	def get_date(self, report):
		data = report.get('data')
		requests = data.get('requests')
		response = requests[0].get('response')
		response_final = response.get('response')
		headers = response_final.get('headers')
		date = headers.get('Date')
		return date

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Urlscan.io"

        malicious = raw["verdicts"]["overall"]["malicious"]
        score = raw["verdicts"]["overall"]["score"]
        tags = raw["verdicts"]["overall"]["score"]
        last_seen = self.get_date()

        if malicious:
            level = 'malicious'
        elif score > 0:
            level = 'suspicious'
        if score == None:
        	score == "Not found"
       	if len(tags) != 0:
        	for tag in tags:
        		taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))

        taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))
        if last_seen != None:
        	taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))

        return {"taxonomies": taxonomies}


    def run(self):
        try:
            records = self.get_results()
            self.report(records)

        except Exception: # Unknown error
            self.unexpectedError("Unknown error while running Urlscan analyzer")



if __name__ == '__main__':
    UrlscanAnalyzer().run()
