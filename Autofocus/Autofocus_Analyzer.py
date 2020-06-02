#!/usr/bin/env python3
# encoding: utf-8
from autofocus import AutoFocusAPI, AFSample, AFServerError, AFClientError, AFSampleAbsent
from cortexutils.analyzer import Analyzer
import requests
import json
from datetime import datetime
import re
AutoFocusAPI.api_key = "Your API key here"

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
        if self.service == "search_ioc":
            self.headers = {"apiKey": self.autofocus_key, "Content-Type": "application/json"}
        else:
            self.headers = {"Content-Type": "application/json"}
            self.data = {"apiKey": self.autofocus_key, "coverage": "true", "sections": ["coverage", "http", "dns"]}

    def get_request(self):
        indicator_type_initial = str(self.data_type)
        if indicator_type_initial == "ip":
           indicator_type = "ipv4_address"
           #field = "alias.domain"
           field = "sample.tasks.dns"
           #field = "sample.tasks.http"
        elif indicator_type_initial == "domain":
           indicator_type = "domain"
           field = "sample.tasks.dns"
        indicator_value = str(self.getData())
        self.params = {"indicatorType": indicator_type, "indicatorValue": indicator_value, "includeTags": "true"}
        url = str(self.basic_url)
        r = requests.get(url, params=self.params, headers=self.headers)
        if r.status_code == 200:
           res_search = r.json()
           indicator = res_search.get('indicator')
           tags = res_search.get('tags')
           relations = []
           search = {"operator":"all","children":[{"field":field,"operator":"contains","value":indicator_value}]}
           for sample in AFSample.search(search):
               relations.append({'metadata': sample.serialize(),'tags': [tag.serialize() for tag in sample.__getattribute__('tags')]})
           res = {'metadata': indicator, 'tags': tags, 'relations': relations}
           return res
        else:
           self.error("Autofocus returns %s" % r.status_code)


    def get_analysis(self):
        indicator_value = str(self.getData())
        url_analysis = "https://autofocus.paloaltonetworks.com/api/v1.0/sample/"
        query = "/analysis"
        url = url_analysis + indicator_value + query
        data = json.dumps(self.data)
        r = requests.post(url, data=data, headers=self.headers)
        if (r.status_code == 200):
           res_search = r.json()
        else:
           res_search = {}
        return res_search

    def execute_autofocus_service(self):
        data = self.getData()
        AutoFocusAPI.api_key = self.autofocus_key
        sample = AFSample.get(data)
        analysis = self.get_analysis()
        res = {'metadata': sample.serialize(),'tags': [tag.serialize() for tag in sample.__getattribute__('tags')], 'analysis': analysis}
        print(res)
        return res

    def summary(self, raw):
        taxonomies = []
        namespace = "PaloAltoNetworks"

        if "metadata" in raw:
            if self.service == "search_hash":
                verdict = raw.get('metadata').get('verdict')
                if verdict == "greyware":
                    value = "3"
                    level = "suspicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict))
                elif verdict == "phising":
                    value = "4"
                    level = "malicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict))
                elif verdict == "malware":
                    value = "5"
                    level = "malicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict))
                else:
                    value = "0"
                    level = "safe"
                first_seen = raw.get('metadata').get('create_date')
                if first_seen != None:
                    taxonomies.append(self.build_taxonomy(level,namespace,"First_seen",first_seen))
                last_seen = raw.get('metadata').get('finish_date')
                if last_seen != None:
                    taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
                regions = raw.get('metadata').get('regions')
                if len(regions) != 0:
                   for r in regions:
                       taxonomies.append(self.build_taxonomy(level,namespace,"Region",r.upper()))
            else:
                verdict_dict = raw.get('metadata').get('latestPanVerdicts')
                if verdict_dict.get('WF_SAMPLE') != None:
                    verdict = verdict_dict.get('WF_SAMPLE')
                elif verdict_dict.get('PAN_DB') != None:
                    verdict = verdict_dict.get('PAN_DB')
                else:
                    verdict = None
                if verdict == "GREYWARE":
                    value = "3"
                    level = "suspicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict.lower()))
                elif verdict == "PHISING":
                    value = "4"
                    level = "malicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict.lower()))
                elif verdict == "MALWARE" or verdict == "C2":
                    value = "5"
                    level = "malicious"
                    taxonomies.append(self.build_taxonomy(level,namespace,"Verdict",verdict.lower()))
                else:
                    value = "0"
                    level = "safe"
                first_seen_timestamp = raw.get('metadata').get('firstSeenTsGlobal')
                if first_seen_timestamp != None:
                    first_seen_timestamp_str = str(first_seen_timestamp)
                    first_seen_timestamp_cut = first_seen_timestamp_str[:-3]
                    first_seen_timestamp_result = int(first_seen_timestamp_cut)
                    first_seen = datetime.fromtimestamp(first_seen_timestamp_result).isoformat()
                    taxonomies.append(self.build_taxonomy(level,namespace,"First_seen",first_seen))
                last_seen_timestamp = raw.get('metadata').get('lastSeenTsGlobal')
                if last_seen_timestamp != None:
                    last_seen_timestamp_str = str(last_seen_timestamp)
                    last_seen_timestamp_cut = last_seen_timestamp_str[:-3]
                    last_seen_timestamp_result = int(last_seen_timestamp_cut)
                    last_seen = datetime.fromtimestamp(last_seen_timestamp_result).isoformat()
                    taxonomies.append(self.build_taxonomy(level,namespace,"Last_seen",last_seen))
                
        taxonomies.append(self.build_taxonomy(level,namespace,"Score",value))
                
        return {'taxonomies': taxonomies}


    def artifacts(self, report):
        artifacts = []
        ips = []
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
                  if tag_name.find("CVE") >= 0:
                     observable = {'dataType': 'vulnerability', 'data': tag_name}
                  else:
                     observable = {'dataType': 'exploit', 'data': tag_name}
               else:
                  observable = {'dataType': 'attack_pattern', 'data': tag_name}
               if observable not in artifacts:
                  artifacts.append(observable)

        if self.service == "search_hash":
          try:
            analysis = report.get('analysis')
            if analysis != None:
                coverage = analysis.get('coverage')
                if coverage != None:
                    malware_sig = coverage.get('wf_av_sig')
                    dns_sig = coverage.get('dns_sig')
                    fileurl_sig = coverage.get('fileurl_sig')
                    url_cat = coverage.get('url_cat')
                    if len(malware_sig) != 0:
                        for sig in malware_sig:
                            sig_name = sig.get('name')
                            observable_sig = {'dataType': 'malware_family', 'data': sig_name}
                            if observable_sig not in artifacts:
                               artifacts.append(observable_sig)
                    if len(dns_sig) != 0:
                        for domain in dns_sig:
                            dns_name = domain.get('domain')
                            observable_dns = {'dataType': 'domain', 'data': dns_name}
                            if observable_dns not in artifacts:
                               artifacts.append(observable_dns)
                    if len(url_cat) != 0:
                        for url in url_cat:
                            url_name = url.get('url')
                            observable_url = {'dataType': 'domain', 'data': url_name}
                            if observable_url not in artifacts:
                               artifacts.append(observable_url)
                    analysis_dns = analysis.get('dns')
                    if analysis_dns != None:
                        for platform in analysis_dns.keys():
                            print(platform)
                            if platform != None:
                               dns_platform = analysis_dns.get(platform)
                               for d in dns_platform:
                                 line_dns = d.get('line')
                                 regex_dns = re.findall(r'(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})', line_dns)
                                 if regex_dns is not None and regex_dns not in ips:
                                    ips.append(regex_dns)
                    analysis_http = analysis.get('http')
                    if analysis_http != None:
                        for platform in analysis_http.keys():
                            print(platform)
                            if platform != None:
                               http_platform = analysis_http.get(platform)
                               for h in http_platform:
                                 line_http = h.get('line')
                                 regex_http = re.findall(r'(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})', line_http)
                                 if regex_http is not None and regex_http not in ips:
                                    ips.append(regex_http)
                    if len(ips) != 0:
                       for ip in ips:
                           if len(ip) != 0:
                              dir_ip = ip[0]
                              observable_ip = {'dataType': 'ip', 'data': dir_ip}
                              artifacts.append(observable_ip)
            metadata = report.get('metadata')
            md5 = metadata.get('md5')
            if md5 != None:
              observable_md5 = {'dataType': 'hash', 'data': md5}
              if observable_md5 not in artifacts:
                  artifacts.append(observable_md5)
            sha1 = metadata.get('sha1')
            if sha1 != None:
              observable_sha1 = {'dataType': 'hash', 'data': sha1}
              if observable_sha1 not in artifacts:
                  artifacts.append(observable_sha1)          
            sha256 = metadata.get('sha256')
            if sha256 != None:
              observable_sha256 = {'dataType': 'hash', 'data': sha256}
              if observable_sha256 not in artifacts:
                  artifacts.append(observable_sha256)
                  
          except Exception as e:
            print(e)
            pass

        if self.service == "search_ioc":
            relations = report.get('relations')
            if len(relations) != 0:
                for relation in relations:
                    if "metadata" in relation:
                        hash_sha256 = relation.get('metadata').get('sha256')
                        hash_md5 = relation.get('metadata').get('md5')
                        hash_sha1 = relation.get('metadata').get('sha1')
                        if hash_sha256 != None:
                            observable_hash_sha256 = {'dataType': 'hash', 'data': hash_sha256}
                            if observable_hash_sha256 not in artifacts:
                               artifacts.append(observable_hash_sha256)
                        if hash_md5 != None:
                            observable_hash_md5 = {'dataType': 'hash', 'data': hash_md5}
                            if observable_hash_md5 not in artifacts:
                               artifacts.append(observable_hash_md5)
                        if hash_sha1 != None:
                            observable_hash_sha1 = {'dataType': 'hash', 'data': hash_sha1}
                            if observable_hash_sha1 not in artifacts:
                               artifacts.append(observable_hash_sha1)

        return artifacts


    def run(self):
        try:
            if self.service == "search_hash":
                records = self.execute_autofocus_service()
            else:
                records = self.get_request()

            self.report(records)

        except AFSampleAbsent as e: # Sample not in Autofocus
            self.report({'metadata': 'not found', 'tags': []})
        except AFServerError as e: # Server error
            self.unexpectedError(e)
        except AFClientError as e: # Client error
            self.unexpectedError(e)
        except Exception as e: # Unknown error
            print(e)
            self.unexpectedError("Unknown error while running Autofocus analyzer")

if __name__ == '__main__':
    AutoFocusAnalyzer().run()
