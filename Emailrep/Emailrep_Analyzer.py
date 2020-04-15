#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from Emailrep import EmailRepException, EmailRep


class EmailRepAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "EmailRep"

        suspicious = raw.get("suspicious", False)
        reputation = raw.get('reputation')
        malicious_activity = raw.get('details').get('malicious_activity', False)
        malicious_activity_recent = raw.get('details').get('malicious_activity_recent', False)
        blacklisted = raw.get('details').get('blacklisted', False)
        data_breach = raw.get('details').get('data_breach', False)
        spam = raw.get('details').get('spam', False)
        last_seen = raw.get('details').get('last_seen', None)

        if reputation == 'low':
            if suspicious:
                if malicious_activity and malicious_activity_recent:
                    if blacklisted or data_breach or spam:
                        score = "5/5"
                        level = "malicious"
                    else:
                        score = "4/5"
                        level = "malicious"
                else:
                    score = "3/5"
                    level = "suspicious"
            else:
                score = "2/5"
                level = "info"
        else:
            if suspicious:
                if malicious_activity:
                    if blacklisted or data_breach or spam:
                        score = "4/5"
                        level = "malicious"
                    else:
                        score = "3/5"
                        level = "suspicious"
                else:
                    score = "2/5"
                    level = "info"
            else:
                if malicious_activity:
                    if blacklisted or data_breach or spam:
                        score = "3/5"
                        level = "suspicious"
                    else:
                        score = "2/5"
                        level = "info"
                else:
                    if blacklisted or data_breach or spam:
                        score = "2/5"
                        level = "info"
                    else:
                        score = "1/5"
                        level = "info"

        taxonomies.append(
            self.build_taxonomy(level, namespace, "Score", score)
        )

        taxonomies.append(
            self.build_taxonomy(level, namespace, "Last_seen", last_seen)
        )

        return {"taxonomies": taxonomies}
        

    def run(self):
        data = self.get_data()

        try:
            emailRep = EmailRep()
            result = emailRep.get(data)
            self.report(result)
        except EmailRepException as e:
            self.error(str(e))


if __name__ == "__main__":
    EmailRepAnalyzer().run()
