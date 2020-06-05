#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.analyzer import Analyzer
from shodan_api import ShodanAPIPublic
from shodan.exception import APIError


class ShodanAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.shodan_key = self.get_param('config.key', None, 'Missing Shodan API key')
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.shodan_client = None


    def encode(self, x):
            if isinstance(x, str):
                return x.encode('utf-8', 'ignore').decode('utf-8', 'ignore')
            elif isinstance(x, dict):
                return {k: self.encode(v) for k, v in x.items()}
            elif isinstance(x, list):
                return [self.encode(k) for k in x]
            else:
                return x

    def execute_shodan_service(self, data):
        if self.service in ['host', 'host_history']:
            results = {'host': self.shodan_client.host(data, history=True if self.service == 'host_history' else False)}
            return results
        elif self.service == 'dns_resolve':
            results = {'records': self.shodan_client.dns_resolve(data)}
            return results
        elif self.service == 'reverse_dns':
            results = {'records': self.shodan_client.reverse_dns(data)}
            return results
        elif self.service == 'search':
            page = self.get_param('parameters.page', 1, None)
            results = {'records': self.shodan_client.search(data, page)}
            return results
        elif self.service == 'info_domain':
            results = {'info_domain': self.shodan_client.info_domains(data)}
            return results
        else:
            self.error("Unknown service")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Shodan"
        predicate = "Location"
        if self.service in ['host', 'host_history']:
            if 'country_name' in raw['host']:
                value = raw['host']['country_name']
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            if 'org' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'Org', raw['host']['org']))
            # Added information about tags and last seen date
            if 'tags' in raw['host']:
                tags = raw['host']['tags']
                for tag in tags:
                    taxonomies.append(self.build_taxonomy(level, namespace, 'Tag', tag))
            if 'last_update' in raw['host']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'Last_seen', raw['host']['last_update']))
        elif self.service == 'info_domain':
            if 'ips' in raw['info_domain']:
                value = "{}".format(len(raw['info_domain']['ips']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'IPs', value))
            if 'all_domains' in raw['info_domain']:
                value = "{}".format(len(raw['info_domain']['all_domains']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'Domains', value))
            if 'asn' in raw['info_domain']:
                value = "{}".format(len(raw['info_domain']['asn']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ASNs', value))
            if 'isp' in raw['info_domain']:
                value = "{}".format(len(raw['info_domain']['isp']))
                taxonomies.append(self.build_taxonomy(level, namespace, 'ISPs', value))
            # Added information about country name and organization
            if 'country_name' in raw['info_domain']['location']['country_name']:
                value = raw['info_domain']['location']['country_name']
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
            if 'org' in raw['info_domain']['org']:
                taxonomies.append(self.build_taxonomy(level, namespace, 'Org', raw['info_domain']['org']))               
        elif self.service == 'dns_resolve':
            value = "{}".format(len(raw['records']))
            taxonomies.append(self.build_taxonomy(level, namespace, 'DNS resolutions', value))
        elif self.service == 'reverse_dns':
            nb_domains = 0
            for k in raw['records'].keys():
                nb_domains += len(raw['records'][k])
            value = "{}".format(len(nb_domains))
            taxonomies.append(self.build_taxonomy(level, namespace, 'Reverse DNS resolutions', value))
        elif self.service == 'search':
            value = "{}".format(raw['records']['total'])
            taxonomies.append(self.build_taxonomy(level, namespace, 'Hosts', value))
        return {'taxonomies': taxonomies}
        

    # Added function artifacts in order to extract relations between IPs or domains as observables
    def artifacts(self, report):
        artifacts = []
        if self.service == 'reverse_dns':
            for k in report['records'].keys():
                domains = report['records'][k]
                for domain in domains:
                    if domain != None:
                       observable_domain = {'dataType': 'domain', 'data': domain}
                       if observable_domain not in artifacts:
                          artifacts.append(observable_domain)
        if self.service == 'dns_resolve':
            for k in report['records'].keys():
                ip = report['records'][k]
                if ip != None:
                   observable_ip = {'dataType': 'ip', 'data': ip}
                   if observable_ip not in artifacts:
                      artifacts.append(observable_ip)
        return artifacts
        

    def run(self):
        try:
            self.shodan_client = ShodanAPIPublic(self.shodan_key)
            data = self.get_param('data', None, 'Data is missing')
            results = self.execute_shodan_service(data)
            self.report(self.encode(results))
        except APIError as e:
            self.error(str(e))
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    ShodanAnalyzer().run()
