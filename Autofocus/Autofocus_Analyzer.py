#!/usr/bin/env python3
# encoding: utf-8
from autofocus import AutoFocusAPI, AFSample, AFServerError, AFClientError, AFSampleAbsent
from cortexutils.analyzer import Analyzer
import requests
from datetime import datetime

AutoFocusAPI.api_key = "Your Api key here"

# Main analyzer
class AutoFocusAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam(
            'config.service', None, 'Service parameter is missing')
        self.autofocus_key = self.getParam(
            'config.apikey', None, 'Missing AutoFocus API key')
        #URL api only for data types: IP, domain and url
        self.basic_url = "https://autofocus.paloaltonetworks.com/api/v1.0/tic"
        self.headers = {"apiKey": self.autofocus_key, "Content-Type": "application/json"}

    def execute_autofocus_service(self):
        data = self.getData()
        AutoFocusAPI.api_key = self.autofocus_key
        sample = AFSample.get(data)
        res = {'metadata': sample.serialize(),'tags': [tag.serialize() for tag in sample.__getattribute__('tags')]}
        return res

    def get_request(self):
        indicator_type_initial = str(self.data_type)
        if indicator_type_initial == "ip":
           indicator_type = "ipv4_address"
        elif indicator_type_initial == "domain":
           indicator_type = "domain"
        elif indicator_type_initial == "url":
           indicator_type = "url"
        indicator_value = str(self.getData())
        self.params = {"indicatorType": indicator_type, "indicatorValue": indicator_value, "includeTags": "true"}
        url = str(self.basic_url)
        r = requests.get(url, params=self.params, headers=self.headers)
        res_search = r.json()
        indicator = res_search.get('indicator')
        tags = res_search.get('tags')
        res = {'metadata': indicator, 'tags': tags}
        return res

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "PaloAltoNetworks"
        value = "1/5"

        if "metadata" in raw:
            if self.service == "search_hash":
                verdict = raw.get('metadata').get('verdict')
                last_seen = raw.get('metadata').get('finish_date')
            else:
                verdict_dict = raw.get('metadata').get('latestPanVerdicts')
                if verdict_dict.get('WF_SAMPLE') != None:
                    verdict = verdict_dict.get('WF_SAMPLE')
                elif verdict_dict.get('PAN_DB') != None:
                    verdict = verdict_dict.get('PAN_DB')
                else:
                    verdict = None
                last_seen_timestamp = raw.get('metadata').get('lastSeenTsGlobal')
                if last_seen_timestamp != None:
                    last_seen_timestamp_str = str(last_seen_timestamp)
                    last_seen_timestamp_cut = last_seen_timestamp_str[:-3]
                    last_seen_timestamp_result = int(last_seen_timestamp_cut)
                    last_seen = datetime.fromtimestamp(last_seen_timestamp_result).isoformat()
                else:
                    last_seen = "Not found"
            if verdict == "benign" or verdict == "BENIGN":
                value = "0/5"
                level = "safe"
            elif verdict == "greyware" or verdict == "GREYWARE":
                value = "3/5"
                level = "suspicious"
            elif verdict == "phising" or verdict == "PHISING":
                value = "4/5"
                level = "malicious"
            elif verdict == "malware" or verdict == "MALWARE" or verdict == "C2":
                value = "5/5"
                level = "malicious"
            taxonomies.append(self.build_taxonomy(level,namespace,"Score",value))
            taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
        else:
            value = "Not found"
            taxonomies.append(self.build_taxonomy(level,namespace,"Autofocus",value))
        return {'taxonomies': taxonomies}

    def artifacts(self, report):
        artifacts = []
        tags = report.get('tags')
        if len(tags) != 0:
           for tag in tags:
               if self.service == "search_hash":
                  tag_name = tag.get('name')
               else:
                  tag_name = tag.get('tag_name')

               tag_class_id = tag.get('tag_class_id')
               if tag_class_id == 1:
                  observable = {'dataType': 'threat_actor', 'data': tag_name}
               elif tag_class_id == 2:
                  observable = {'dataType': 'campaign', 'data': tag_name}
               elif tag_class_id == 3:
                  observable = {'dataType': 'malware_family', 'data': tag_name}
               elif tag_class_id == 4:
                  observable = {'dataType': 'exploit', 'data': tag_name}
               else:
                  observable = {'dataType': 'malicious_behaviour', 'data': tag_name}

               artifacts.append(observable)

        return artifacts

    def run(self):
        try:
            if self.service == "search_hash":
                records = self.execute_autofocus_service()
            else:
                records = self.get_request()

            self.report(records)

        except AFSampleAbsent as e: # Sample not in Autofocus
            self.error('Unknown sample in Autofocus')
        except AFServerError as e: # Server error
            self.unexpectedError(e)
        except AFClientError as e: # Client error
            self.unexpectedError(e)
        except Exception: # Unknown error
            self.unexpectedError("Unknown error while running Autofocus analyzer")

if __name__ == '__main__':
    AutoFocusAnalyzer().run()