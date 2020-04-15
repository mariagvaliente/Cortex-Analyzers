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

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "PaloAltoNetworks"

        if self.service == "search_hash":
            if "metadata" in raw:
                verdict = raw.get('metadata').get('verdict')
                last_seen = raw.get('metadata').get('finish_date')
                value = "1/5"
                if verdict == "malware":
                    value = "5/5"
                    level = "malicious"
                elif verdict == "phising":
                    value = "4/5"
                    level = "suspicious"
                elif verdict == "greyware":
                    value = "3/5"
                    level = "suspicious"
                else:
                    value = "0/5"
                    level = "safe"
                taxonomies.append(self.build_taxonomy(level,namespace,"Score",value))
                taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
            else:
                value = "Not found"
                taxonomies.append(self.build_taxonomy(level,namespace,"Autofocus",value))

            tags = raw.get('tags')
            for tag in tags:
                tag_name = tag.get('name')
                tag_class = tag.get('tag_class')
                taxonomies.append(self.build_taxonomy(level,namespace,tag_class,tag_name))
        else:
            indicator = raw.get('indicator')
            if indicator != None:
                verdict = indicator.get('latestPanVerdicts')
                verdict_WF = verdict.get('WF_SAMPLE')
                verdict_PB = verdict.get('PAN_DB')
                if (verdict_WF or verdict_PB) != None:
                    if (verdict_WF or verdict_PB) == 'BENIGN':
                        value = "0/5"
                        level = "safe"
                    elif (verdict_WF or verdict_PB) == 'GREYWARE':
                        value = "3/5"
                        level = "suspicious"
                    elif (verdict_WF or verdict_PB) == 'PHISING':
                        value = "4/5"
                        level = "malicious"
                    elif (verdict_WF or verdict_PB) == ('MALWARE') or ('C2'):
                        value = "5/5"
                        level = "malicious"
                    else:
                        value = "1/5"
                        level = "info"
                else:
                    value = "1/5"
                    level = "info"
                taxonomies.append(self.build_taxonomy(level,namespace,"Score",value))
                last_seen_timestamp = indicator.get('lastSeenTsGlobal')
                last_seen_timestamp_str = str(last_seen_timestamp)
                last_seen_timestamp_cut = last_seen_timestamp_str[:-3]
                last_seen_timestamp_result = int(last_seen_timestamp_cut)
                last_seen = datetime.fromtimestamp(last_seen_timestamp_result)
                taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
            else:
                value = "Not found"
                taxonomies.append(self.build_taxonomy(level,namespace,"Autofocus",value))

        return {'taxonomies': taxonomies}

    def artifacts(self, report):
        artifacts = []
        tags = report.get('tags')
        for tag in tags:
            tag_name = tag.get('name')
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
                self.report(records)
            else:
                indicator_type = str(self.data_type)
                indicator_value = str(self.getData())
                self.params = {"indicatorType": indicator_type, "indicatorValue": indicator_value, "includeTags": "true"}
                url = str(self.basic_url)
                r = requests.get(url, params=self.params, headers=self.headers)
                res_search = r.json()
                self.report(res_search)

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