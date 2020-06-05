#!/usr/bin/env python3
# encoding: utf-8

import requests

from collections import defaultdict, OrderedDict
from cortexutils.analyzer import Analyzer


class GreyNoiseAnalyzer(Analyzer):
    """
    GreyNoise API docs: https://github.com/GreyNoise-Intelligence/api.greynoise.io
    """

    @staticmethod
    def _get_level(current_level, new_classification):
        """
        Map GreyNoise classifications to Cortex maliciousness levels.
        Accept a Cortex level and a GreyNoise classification, the return the more malicious of the two.
        :param current_level: A Cortex maliciousness level
            https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md#output
        :param new_classification: A classification field value from a GreyNoise record
            https://github.com/GreyNoise-Intelligence/api.greynoise.io#v1queryip
        :return: The more malicious of the 2 submitted values as a Cortex maliciousness level
        """

        classification_level_map = OrderedDict([
            ('info', 'info'),
            ('benign', 'safe'),
            ('suspicious', 'suspicious'),
            ('malicious', 'malicious')
        ])
        levels = classification_level_map.values()

        new_level = classification_level_map.get(new_classification, 'info')
        print(new_level)
        new_index = list(levels).index(new_level)
        print(new_index)

        try:
            current_index = list(levels).index(current_level)
            print(current_index)
        except ValueError:  # There is no existing level
            current_index = -1

        return new_level if new_index > current_index else current_level

    def run(self):

        if self.data_type == "ip":
            api_key = self.get_param('config.key', None)
            url = 'https://api.greynoise.io/v2/experimental/gnql?query=ip:%s' % self.get_data()

            if api_key:
                headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Key': '%s' % api_key }
            else:
                headers = {'Content-Type': 'application/x-www-form-urlencoded' }

            response = requests.get(url, headers=headers)
            if not (200 <= response.status_code < 300):
                self.error('Unable to query GreyNoise API\n{}'.format(response.text))
            self.report(response.json())

        else:
            self.notSupported()

    def summary(self, raw):
        """
        Return one taxonomy summarizing the reported tags
            If there is only one tag, use it as the predicate
            If there are multiple tags, use "entries" as the predicate
            Use the total count as the value
            Use the most malicious level found
        Examples:
        Input
        {
            "actor": SCANNER1,
            "classification": ""
        }
        Output
        GreyNoise:SCANNER1 = 1 (info)
        Input
        {
            "actor": SCANNER1,
            "classification": "malicious"
        },
        {
            "classification": "benign"
        }
        Output
        GreyNoise:SCANNER1 = 2 (malicious)
        Input
        {
            "actor": SCANNER1,
            "classification": ""
        },
        {
            "actor": SCANNER1,
            "classification": "safe"
        },
        {
            "actor": SCANNER2,
            "classification": ""
        }
        Output
        GreyNoise:entries = 3 (safe)
        """

        try:
            taxonomies = []
            if raw.get('data'):
                final_level = None
                taxonomy_data = defaultdict(int)
                for record in raw.get('data', []):
                    actor = record.get('actor', 'unknown')
                    classification = record.get('classification', 'unknown')
                    taxonomy_data[actor] += 1
                    final_level = self._get_level(final_level, classification)
                    print(final_level)

                if len(taxonomy_data) > 1:  # Multiple tags have been found
                    taxonomies.append(self.build_taxonomy(final_level, 'GreyNoise', 'entries', len(taxonomy_data)))
                else:  # There is only one tag found, possibly multiple times
                    for actor, count in taxonomy_data.items():
                        taxonomies.append(self.build_taxonomy(final_level, 'GreyNoise', actor, count))

                # Added scores mapping with the final level
                if final_level == "malicious":
                   score = "4"
                elif final_level == "info":
                   score = "1"
                else:
                   score = "0"
                taxonomies.append(self.build_taxonomy(final_level,'GreyNoise',"Score",score))

                # Added information about first and last seen dates
                first_seen = record.get('first_seen', None)
                last_seen = record.get('last_seen', None)
                if first_seen != None:
                   taxonomies.append(self.build_taxonomy(final_level,'GreyNoise',"First_seen",first_seen))
                if last_seen != None:
                   taxonomies.append(self.build_taxonomy(final_level,'GreyNoise',"Last_seen",last_seen))
                # Added information about geolocation
                country = record.get('metadata').get('country', None)
                city = record.get('metadata').get('city', None)
                if country != None:
                   taxonomies.append(self.build_taxonomy(final_level,'GreyNoise',"Country",country))
                if city != None:
                   taxonomies.append(self.build_taxonomy(final_level,'GreyNoise',"City",city))


            else:
                taxonomies.append(self.build_taxonomy('info', 'GreyNoise', 'Records', 'None'))

            return {"taxonomies": taxonomies}


        except Exception as e:
            print(e)
            self.error('Summary failed\n{}'.format(e.message))


    # Added artifacts function in order to extract domains related as observables
    def artifacts(self, report):
        artifacts = []
        if report.get('data'):
            for record in report.get('data'):
                if record['metadata']['rdns'] != "" and record['metadata']['rdns'] != None:
                   observable_domain = {'dataType': 'domain', 'data': record['metadata']['rdns']}
                   if observable_domain not in artifacts:
                      artifacts.append(observable_domain)
              
        return artifacts


if __name__ == '__main__':
    GreyNoiseAnalyzer().run()