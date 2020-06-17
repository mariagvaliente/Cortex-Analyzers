#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import urllib
import hashlib
import io
import re
from cortexutils.analyzer import Analyzer


class OTXQueryAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)        
        self.otx_key = self.get_param('config.key', None, 'Missing OTX API key')

    def _get_headers(self):
        return {
            'X-OTX-API-KEY': self.otx_key,
            'Accept': 'application/json'
        }

    def otx_query_ip(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/" % data
        headers = self._get_headers()
        sections = [
            'general',
            'reputation',
            'geo',
            'malware',
            'url_list',
            'passive_dns'
        ]
        ip_ = {}
        # Added information about first and last seen dates
        last_seen_dates = []
        first_seen_dates = []
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)

            ip_general = ip_['general']
            ip_geo = ip_['geo']
            pulses = ip_general.get('pulse_info').get('pulses')
            if pulses != None:
               for pulse in pulses:
                   last_seen_dates.append(pulse.get('modified'))
                   first_seen_dates.append(pulse.get('created'))
            if len(last_seen_dates) != 0:
               last_seen = last_seen_dates[0]
            else:
               last_seen = None
            if len(first_seen_dates) != 0:
               first_seen = first_seen_dates[-1]
            else:
               first_seen = None
               
            # Added a score based on the ip reputation
            reputation = ip_['reputation']['reputation']
            print(reputation)
            
            if reputation != None:
               threat_score = reputation.get('threat_score')
               if threat_score == 7:
                  my_score = '0'
               elif 5 <= threat_score <= 6:
                  my_score = '2'
               elif threat_score == 4:
                  my_score = '3'
               elif threat_score == 3:
                  my_score = '4'
               else:
                  my_score = '5'
            else:
               my_score = '1'
            
            self.report({
                'result': 'found',
                'pulse_count': ip_general.get('pulse_info', {}).get('count', "0"),
                'pulses': ip_general.get('pulse_info', {}).get('pulses', "-"),
                'first_seen': first_seen,
                'last_seen': last_seen,
                'score': my_score,
                'whois': ip_general.get('whois', "-"),
                'continent_code': ip_geo.get('continent_code', "-"),
                'country_code': ip_geo.get('country_code', "-"),
                'country_name': ip_geo.get('country_name', "-"),
                'city': ip_geo.get('city', "-"),
                'longitude': ip_general.get('longitude', "-"),
                'latitude': ip_general.get('latitude', "-"),
                'asn': ip_geo.get('asn', "-"),
                'malware_samples': ip_.get('malware', {}).get('result', "-"),
                'url_list': ip_.get('url_list', {}).get('url_list', "-"),
                'passive_dns': ip_.get('passive_dns', {}).get('passive_dns', "-")
            })
        except Exception:
            self.report({'result': 'not found'})

    def otx_query_domain(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/domain/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'geo', 'malware', 'url_list', 'passive_dns']
        ip_ = {}
        # Added information about first and last seen dates
        last_seen_dates = []
        first_seen_dates = []
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)
            pulses = ip_.get('general').get('pulse_info').get('pulses')
            if pulses != None:
               for pulse in pulses:
                   last_seen_dates.append(pulse.get('modified'))
                   first_seen_dates.append(pulse.get('created'))
            if len(last_seen_dates) != 0:
               last_seen = last_seen_dates[0]
            else:
               last_seen = None
            if len(first_seen_dates) != 0:
               first_seen = first_seen_dates[-1]
            else:
               first_seen = None
            
            # Added a score based on Google Safe Browsing verdict
            list_verdict = ip_['url_list']['url_list']
            print(list_verdict)
            if len(list_verdict) != 0:
               gsb = list_verdict[0].get('gsb')
               if len(gsb) == 0:
                  # Not identified as malicious
                  my_score = '0'
               else:
                  # Generic, malware
                  my_score = '5'
            else:
               # Not analyzed
               my_score = '1'

            result = {
                'result': 'found',
                'pulse_count': ip_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                'pulses': ip_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                'first_seen': first_seen,
                'last_seen': last_seen,
                'score': my_score,
                'whois': ip_.get('general', {}).get('whois', "-"),
                'malware_samples': ip_.get('malware', {}).get('result', "-"),
                'url_list': ip_.get('url_list', {}).get('url_list', "-"),
                'passive_dns': ip_.get('passive_dns', {}).get('passive_dns', "-")
            }

            try:
                result.update({
                    'continent_code': ip_.get('geo', {}).get('continent_code', "-"),
                    'country_code': ip_.get('geo', {}).get('country_code', "-"),
                    'country_name': ip_.get('geo', {}).get('country_name', "-"),
                    'city': ip_.get('geo', {}).get('city', "-"),
                    'asn': ip_.get('geo', {}).get('asn', "-")
                })
            except Exception:
                pass

            self.report(result)
        except Exception:
            self.report({'result': 'not found'})

    def otx_query_file(self, data):
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/file/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'analysis']
        ip_ = {}
        # Added information about first and last seen dates
        last_seen_dates = []
        first_seen_dates = []
        try:
            for section in sections:
                queryurl = baseurl + section
                ip_[section] = json.loads(requests.get(queryurl, headers=headers).content)
            pulses = ip_.get('general').get('pulse_info').get('pulses')
            if len(pulses) != 0: 
               for pulse in pulses:
                   last_seen_dates.append(pulse.get('modified'))
                   first_seen_dates.append(pulse.get('created'))
            if len(last_seen_dates) != 0:
               last_seen = last_seen_dates[0]
            else:
               last_seen = None
            if len(first_seen_dates) != 0:
               first_seen = first_seen_dates[-1]
            else:
               first_seen = None

            # Added a score based on cuckoo score or antivirus results
            if ip_['analysis']['analysis']:
                print(ip_['analysis']['analysis'])         
                cuckoo_score = ip_['analysis']['analysis'].get('plugins').get('cuckoo')
                result_msdefender = ip_['analysis']['analysis'].get('plugins').get('msdefender').get('results')
                result_avast = ip_['analysis']['analysis'].get('plugins').get('avast').get('results')
                result_clamav = ip_['analysis']['analysis'].get('plugins').get('clamav').get('results')
                if cuckoo_score is not None:
                   score = cuckoo_score.get('result').get('info').get('score')
                   if score >= 10.0:
                      my_score = '5'
                   elif 7.0 <= score < 10.0:
                      my_score = '4'
                   elif 5.0 <= score < 7.0:
                      my_score = '3'
                   elif 1.0 <= score < 5.0:
                      my_score = '2'
                   else:
                      my_score = '0'
                elif result_msdefender or result_avast or result_clamav:
                   alerts_msdefender = result_msdefender.get('alerts')
                   alerts_avast = result_avast.get('alerts')
                   alerts_clamav = result_clamav.get('alerts')
                   if alerts_msdefender:
                      for alert in alerts_msdefender:
                          if alert == "Malware infection":
                             verdict_msdefender = 'malware'
                   if alerts_avast:
                      for alert in alerts_avast:
                          if alert == "Malware infection":
                             verdict_avast = 'malware'
                          my_score = '4'
                   if result_clamav:
                      for alert in alerts_clamav:
                          if alert == "Malware infection":
                             verdict_clamav = 'malware'
                   if verdict_msdefender == "Malware infection" or verdict_avast == "Malware infection" or verdict_clamav == "Malware infection":
                      my_score = '5'
                   else:
                      my_score = '1'
                else:
                    my_score = '1'
                
                      
                # file has been analyzed before
                self.report({
                    'result': 'found',
                    'pulse_count': ip_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                    'pulses': ip_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'score': my_score,
                    'malware': ip_.get('analysis', {}).get('malware', "-"),
                    'page_type': ip_.get('analysis', {}).get('page_type', "-"),
                    'sha1': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get('sha1',
                                                                                                               "-"),
                    'sha256': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'sha256', "-"),
                    'md5': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get('md5',
                                                                                                              "-"),
                    'file_class': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'file_class', "-"),
                    'file_type': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'file_type', "-"),
                    'filesize': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'filesize', "-"),
                    'ssdeep': ip_.get('analysis', {}).get('analysis', {}).get('info', {}).get('results', {}).get(
                        'ssdeep')
                })
            else:
                # file has not been analyzed before
                self.report({
                    'errortext': 'File has not previously been analyzed by OTX!',
                    'pulse_count': ip_['general']['pulse_info']['count'],
                    'pulses': ip_['general']['pulse_info']['pulses']
                })
        except Exception:
            self.report({'result': 'not found'})

    def otx_query_url(self, data):
        # urlencode the URL that we are searching for
        data = urllib.parse.quote_plus(data)
        baseurl = "https://otx.alienvault.com:443/api/v1/indicators/url/%s/" % data
        headers = self._get_headers()
        sections = ['general', 'url_list']
        IP_ = {}
        # Added information about first and last seen dates
        last_seen_dates = []
        first_seen_dates = []
        try:
            for section in sections:
                queryurl = baseurl + section
                IP_[section] = json.loads(requests.get(queryurl, headers=headers).content)
            pulses = IP_.get('general').get('pulse_info').get('pulses')
            if pulses != None:
               for pulse in pulses:
                   last_seen_dates.append(pulse.get('modified'))
                   first_seen_dates.append(pulse.get('created'))
            if len(last_seen_dates) != 0:
               last_seen = last_seen_dates[0]
            else:
               last_seen = None
            if len(first_seen_dates) != 0:
               first_seen = first_seen_dates[-1]
            else:
               first_seen = None
               
            # Added a score based on Google Safe Browsing verdict
            list_verdict = IP_['url_list']['url_list']
            print(list_verdict)
            if len(list_verdict) != 0:
               gsb = list_verdict[0].get('gsb')
               if len(gsb) == 0:
                  # Not identified as malicious
                  my_score = '0'
               else:
                  # Generic, malware
                  my_score = '5'
            else:
               # Not analyzed
               my_score = '1'

            self.report({
                'result': 'found',
                'pulse_count': IP_.get('general', {}).get('pulse_info', {}).get('count', "0"),
                'pulses': IP_.get('general', {}).get('pulse_info', {}).get('pulses', "-"),
                'first_seen': first_seen,
                'last_seen': last_seen,
                'score': my_score,
                'alexa': IP_.get('general', {}).get('alexa', "-"),
                'whois': IP_.get('general', {}).get('whois', "-"),
                'url_list': IP_.get('url_list', {}).get('url_list', "-")
            })
        except Exception:
            self.report({'result': 'not found'})

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OTX"
        
        # Added information about scores
        score = raw["score"]
        if score != None:
           if score == '4' or score == '5':
              level = 'malicious'
           elif score == '3':
              level = 'suspicious'
           elif score == '2' or score == '1':
              level = 'info'
           else:
              level = 'safe'
           taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))

        value = "{}".format(raw["pulse_count"])
        taxonomies.append(self.build_taxonomy(level, namespace, "Pulses", value))

        # Added information about dates
        first_seen = raw["first_seen"]
        if first_seen != None:
           taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", first_seen))
        last_seen = raw["last_seen"]
        if last_seen != None:
           taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", last_seen))
        pulses = raw['pulses']
        if len(pulses) != 0:
           for pulse in pulses:
               # Added information about pulse tags
               tags = pulse['tags']
               if len(tags) != 0:
                  for tag in tags:
                      if (self.build_taxonomy(level, namespace, "Tag", tag)) not in taxonomies:
                         taxonomies.append(self.build_taxonomy(level, namespace, "Tag", tag))
        # Added information about geolocation
        if self.data_type == "domain" or self.data_type == "ip":
           if raw['country_name'] != None and raw['country_name'] != "-":
              taxonomies.append(self.build_taxonomy(level, namespace, "Country", raw['country_name']))
           if raw['city'] != None and raw['city'] != "-":
              taxonomies.append(self.build_taxonomy(level, namespace, "City", raw['city']))          
        
        return {"taxonomies": taxonomies}
        
    
    # Added artifacts function in order to extract different type of related observables
    def artifacts(self, report):
        artifacts = []
        if report['result'] == 'found':
            if self.data_type == "domain":
               url_list = report['url_list']
               if url_list and len(url_list) != 0:
                   for url in url_list:
                       observable_url = {'dataType': 'url', 'data': url['url']}
                       if observable_url is not None and observable_url not in artifacts:
                          artifacts.append(observable_url)
               malware_samples = report['malware_samples']
               if malware_samples and malware_samples != "-":
                   for sample in malware_samples:
                       observable_hash = {'dataType': 'hash', 'data': sample}
                       if observable_hash is not None and observable_hash not in artifacts:
                          artifacts.append(observable_hash)
               passive_dns = report['passive_dns']
               if passive_dns and len(passive_dns) != 0:
                  for p in passive_dns:
                      if p['address'] != None:
                         regex_ip = re.findall(r'(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})', p['address'])
                         if len(regex_ip) != 0:
                            dir_ip = regex_ip[0]
                            observable_ip = {'dataType': 'ip', 'data': dir_ip}
                            if observable_ip not in artifacts:
                               artifacts.append(observable_ip)
            elif self.data_type == "ip":
               url_list = report['url_list']
               if url_list and len(url_list) != 0:
                   for url in url_list:
                       observable_url = {'dataType': 'url', 'data': url['url']}
                       if observable_url is not None and observable_url not in artifacts:
                          artifacts.append(observable_url)
               malware_samples = report['malware_samples']
               if malware_samples and malware_samples != "-":
                   for sample in malware_samples:
                       observable_hash = {'dataType': 'hash', 'data': sample}
                       if observable_hash is not None and observable_hash not in artifacts:
                          artifacts.append(observable_hash)
               passive_dns = report['passive_dns']
               if passive_dns and len(passive_dns) != 0:
                   for dns in passive_dns:
                       observable_domain = {'dataType': 'domain', 'data': dns['hostname']}
                       if observable_domain is not None and observable_domain not in artifacts:
                          artifacts.append(observable_domain)
            elif self.data_type == "url":
               url_list = report['url_list']
               if url_list and len(url_list) != 0:
                   for url in url_list:
                       observable_ip = {'dataType': 'ip', 'data': url['result']['urlworker']['ip']}
                       if observable_ip is not None and observable_ip not in artifacts:
                          artifacts.append(observable_ip)
                       observable_sha256 = {'dataType': 'hash', 'data': url['result']['urlworker']['sha256']}
                       if observable_sha256 is not None and observable_sha256 not in artifacts:
                          artifacts.append(observable_sha256)             
                       observable_md5 = {'dataType': 'hash', 'data': url['result']['urlworker']['md5']}
                       if observable_md5 is not None and observable_md5 not in artifacts:
                          artifacts.append(observable_md5)
            elif self.data_type == "hash":
               pulses = report['pulses']
               if pulses and len(pulses) != 0:
                  for pulse in pulses:
                      malware_families = pulse['malware_families']
                      if malware_families and len(malware_families) != 0:
                         for m in malware_families:
                             observable_malware_family = {'dataType': 'malware_family', 'data': m['display_name']}
                             if observable_malware_family is not None and observable_malware_family not in artifacts:
                                artifacts.append(observable_malware_family)
               sha1 = report['sha1']
               if sha1 != None:
                  observable_sha1 = {'dataType': 'hash', 'data': sha1}
                  if observable_sha1 not in artifacts:
                     artifacts.append(observable_sha1)
               sha256 = report['sha256']
               if sha256 != None:
                  observable_sha256 = {'dataType': 'hash', 'data': sha256}
                  if observable_sha256 not in artifacts:
                     artifacts.append(observable_sha256)
               md5 = report['md5']
               if md5 != None:
                  observable_md5 = {'dataType': 'hash', 'data': md5}
                  if observable_md5 not in artifacts:
                     artifacts.append(observable_md5)
                 
        return artifacts
                          
           

    def run(self):
        Analyzer.run(self)
        if self.data_type == 'file':
            hashes = self.get_param('attachment.hashes', None)
            if hashes is None:
                filepath = self.get_param('file', None, 'File is missing')
                sha256 = hashlib.sha256()
                with io.open(filepath, 'rb') as fh:
                    while True:
                        data = fh.read(4096)
                        if not data:
                            break
                        sha256.update(data)
                hash = sha256.hexdigest()
            else:
                # find SHA256 hash
                hash = next(h for h in hashes if len(h) == 64)
            self.otx_query_file(hash)
        elif self.data_type == 'url':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_url(data)
        elif self.data_type == 'domain':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_domain(data)
        elif self.data_type == 'ip':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_ip(data)
        elif self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            self.otx_query_file(data)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    OTXQueryAnalyzer().run()