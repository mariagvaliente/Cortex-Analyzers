#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from emailrep import EmailRep
import datetime


class EmailRepAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.key = self.get_param('config.key', None)


    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EmailRep"

        suspicious = raw.get("suspicious", False)
        if suspicious:
            level = "suspicious"
        else:
            level = "safe"

        # Added an assigned score using email information
        reputation = raw.get("reputation")
        malicious_activity = raw.get("details").get("malicious_activity", False)
        malicious_activity_recent = raw.get("details").get("malicious_activity_recent", False)
        blacklisted = raw.get("details").get("blacklisted", False)
        data_breach = raw.get("details").get("data_breach", False)
        spam = raw.get("details").get("spam", False)

        if reputation == "low":
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
        
        # Added information about first and last seen dates
        first_seen = raw.get("details").get("first_seen", None)
        last_seen = raw.get("details").get("last_seen", None)
        if first_seen != None:
           if first_seen != "never":
             format_date = '%m/%d/%Y' # The date format
             datetime_first_seen = datetime.datetime.strptime(first_seen, format_date).isoformat()
             taxonomies.append(self.build_taxonomy(level, namespace, "First_seen", datetime_first_seen))
        if last_seen != None:
           if last_seen != "never":
             format_date = '%m/%d/%Y' # The date format
             datetime_last_seen = datetime.datetime.strptime(last_seen, format_date).isoformat()
             taxonomies.append(self.build_taxonomy(level, namespace, "Last_seen", datetime_last_seen))
             
             
        references = raw.get("references", 0)

        taxonomies.append(
            self.build_taxonomy(level, namespace, "References", references)
        )


        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            emailRep = EmailRep(self.key)
            result = emailRep.query(data)
            self.report(result)
        except Exception as e:
            self.error(str(e))

    # Added artifacts function in order to extract the domain related with the email as an observable
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


if __name__ == "__main__":
    EmailRepAnalyzer().run()
