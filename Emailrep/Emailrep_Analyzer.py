#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import requests
import datetime


class EmailRepAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.base_url = "https://emailrep.io"
        self.api_key = self.getParam('config.apikey', None, 'Missing Emailrep API key')
        self.headers = {"Key": self.api_key}

    def get(self, email_address):
        url = "{}/{}".format(self.base_url, email_address)
        json = self._request(url)
        json["mail"] = email_address
        return json

    def _request(self, url):
        res = requests.get(url, headers=self.headers)

        if res.status_code != 200:
            raise Exception(
                "emailrep returns {}".format(res.status_code))

        json = res.json()
        status = json.get("status")
        if status == "fail":
            reason = json.get("reason")
            raise Exception(reason)

        return json

    def summary(self, raw):
        taxonomies = []
        namespace = "EmailRep"

        suspicious = raw.get("suspicious", False)
        reputation = raw.get('reputation')
        malicious_activity = raw.get('details').get('malicious_activity', False)
        malicious_activity_recent = raw.get('details').get('malicious_activity_recent', False)
        blacklisted = raw.get('details').get('blacklisted', False)
        data_breach = raw.get('details').get('data_breach', False)
        spam = raw.get('details').get('spam', False)
        first_seen = raw.get('details').get('first_seen', None)
        last_seen = raw.get('details').get('last_seen', None)

        if reputation == 'low':
            if suspicious:
                if malicious_activity and malicious_activity_recent:
                    if blacklisted or data_breach or spam:
                        score = "5"
                        level = "malicious"
                    else:
                        score = "4"
                        level = "malicious"
                else:
                    score = "3"
                    level = "suspicious"
            else:
                score = "2"
                level = "info"
        else:
            if suspicious:
                if malicious_activity:
                    if blacklisted or data_breach or spam:
                        score = "4"
                        level = "malicious"
                    else:
                        score = "3"
                        level = "suspicious"
                else:
                    score = "2"
                    level = "info"
            else:
                if malicious_activity:
                    if blacklisted or data_breach or spam:
                        score = "3"
                        level = "suspicious"
                    else:
                        score = "2"
                        level = "info"
                else:
                    if blacklisted or data_breach or spam:
                        score = "2"
                        level = "info"
                    else:
                        score = "0"
                        level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, "Score", score))
        
        if first_seen != None:
           if first_seen != "never":
             format_date = '%m/%d/%Y' # The date format
             datetime_first_seen = datetime.datetime.strptime(first_seen, format_date).isoformat()
             print(datetime_first_seen)
             taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", datetime_first_seen))
        if last_seen != None:
           if last_seen != "never":
             format_date = '%m/%d/%Y' # The date format
             datetime_last_seen = datetime.datetime.strptime(last_seen, format_date).isoformat()
             print(datetime_last_seen)
             taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", datetime_last_seen))

        return {"taxonomies": taxonomies}
        

    def artifacts(self, report):
        artifacts = []
        domain_exists = report['details']['domain_exists']
        if domain_exists == True:
           domain = report['email'].split('@')[1]
           domain_reputation = report['details']['domain_reputation']
           if domain_reputation != None:
              observable_domain = {'dataType': 'domain', 'data': domain, 'tags': ['Reputation: ' + domain_reputation]}
           else:
              observable_domain = {'dataType': 'domain', 'data': domain} 
           if observable_domain not in artifacts:
              artifacts.append(observable_domain)
              
        return artifacts
        
    
    def run(self):
        data = self.get_data()

        try:
            result = self.get(data)
            self.report(result)
        except Exception as e:
            self.error(str(e))


if __name__ == "__main__":
    EmailRepAnalyzer().run()
