#!/usr/bin/env python3
# encoding: utf-8
import datetime
import json

import requests
from cortexutils.analyzer import Analyzer
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session


class UmbrellaAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.access_token = ''
        self.api_key = ''
        self.api_secret = ''
        self.query_limit = ''
        self.organization_name = ''
        self.organization_id = ''
        self.organizations = {}
        self.risk_safe_limit = self.get_param('config.risk_safe_limit', 30)
        self.risk_sus_limit = self.get_param('config.risk_suspicious_limit', 50)
        self.sample_safe_limit = self.get_param('config.sample_safe_limit', 30)
        self.sample_sus_limit = self.get_param('config.sample_suspicious_limit', 50)

    def _create_headers(self):
        token_url = 'https://management.api.umbrella.com/auth/v2/oauth2/token'
        headers = {'X-Umbrella-OrgID': self.organization_id}
        auth = HTTPBasicAuth(self.api_key, self.api_secret)
        client = BackendApplicationClient(client_id=self.organization_id)
        oauth = OAuth2Session(client=client,
                              )
        oauth_token = oauth.fetch_token(token_url=token_url, auth=auth, headers=headers)
        if oauth_token:
            token = oauth_token['access_token']
            self.headers = {'Content-Type': 'application/json',
                            'Authorization': f'Bearer {token}',
                            # 'Access token': token,
                            }
            return self.headers
        else:
            self.error('Error getting token!')
            exit(1)

    def get_combined_report(self, urls, query):
        headers = {'Authorization': f'Bearer {self.access_token}',
                   'Content-Type': 'application/json'}

        base_url = "https://investigate.api.umbrella.com"
        combined_report = {'data': []}
        for meta, url in urls.items():
            report = {'meta': meta}
            try:
                response = requests.get(f'{base_url}{url}', headers=headers)
                if response.status_code == 200:
                    response_json = response.json()
                    if -1 != meta.find('WHOIS History'):
                        if 'expires' in response_json:
                            new_record = sorted(response_json, key=lambda data: data['expires'], reverse=True)
                            report['records'] = new_record
                    elif -1 != meta.find('Status'):
                        report['query'] = query
                        report['status'] = response_json[query]['status']
                    elif -1 != meta.find('BGP') or -1 != meta.find('Hash'):
                        report['records'] = response_json
                    else:
                        if -1 != meta.find('PDNS') and 'records' in response_json:
                            for record in response_json['records']:
                                record['rr'] = record['rr'].rstrip('.')
                        report.update(response_json)
                    combined_report['data'].append(report)
                else:
                    self.error(f'HTTP error {response.status_code} occurred: {response.text}')
            except Exception as e:
                self.unexpectedError(e)

        return combined_report

    def run_umbrella_samples(self, query):
        urls = {}
        if self.data_type == "hash":
            urls['Hash'] = f'/sample/{query}'
            urls['Hash Connections'] = f'/sample/{query}/connections'
            urls['Hash Behaviors'] = f'/sample/{query}/behaviors'
        else:
            urls['Samples'] = f'/samples/{query}'
        
        combined_report = self.get_combined_report(urls, query)
        combined_report['limits'] = {'safe_limit': self.sample_safe_limit,
                                     'sus_limit': self.sample_sus_limit}

        return combined_report

    def run_umbrella_investigate(self, query):
        urls = {}
        if self.data_type == "domain":
            urls['PDNS Domain'] = f'/pdns/domain/{query}'
            urls['PDNS Name'] = f'/pdns/name/{query}'
            urls['WHOIS History'] = f'/whois/{query}/history'
            urls['Risk Score'] = f'/domains/risk-score/{query}'
            urls['Status'] = f'/domains/categorization/{query}?showLabels'
            urls['Samples'] = f'/samples/{query}'
        elif self.data_type == "ip":
            urls['PDNS IP'] = f'/pdns/ip/{query}'
            urls['BGP'] = f'/bgp_routes/ip/{query}/as_for_ip.json'
        elif self.data_type == "hash":
            urls['Hash'] = f'/sample/{query}'
            urls['Hash Connections'] = f'/sample/{query}/connections'
            urls['Hash Behaviors'] = f'/sample/{query}/behaviors'

        combined_report = self.get_combined_report(urls, query)
        combined_report['data'] = sorted(combined_report['data'], key=lambda data: data['meta'], reverse=False)
        combined_report['limits'] = {'safe_limit': self.risk_safe_limit,
                                     'sus_limit': self.risk_sus_limit}

        return combined_report

    def run_umbrella_reports(self, destination):
        headers = self._create_headers()
        base_url = "https://reports.api.umbrella.com"
        url = ''
        if self.data_type == "domain" or self.data_type == "fqdn":
            url = f'{base_url}/v2/organizations/{self.organization_id}/activity/dns?from=-30days&to=now&limit={self.query_limit}&domains={destination}'
        elif self.data_type == "ip":
            url = f'{base_url}/v2/organizations/{self.organization_id}/activity/dns?from=-30days&to=now&limit={self.query_limit}&ip={destination}'
        elif self.data_type == "url":
            url = f'{base_url}/v2/organizations/{self.organization_id}/activity/dns?from=-30days&to=now&limit={self.query_limit}&urls={destination}'

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                record = json.loads(response.text)
                return record
            else:
                self.error(f'HTTP error {response.status_code} occurred: {response.text}')
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        namespace = 'Umbrella'

        if 'Investigate' == self.service:
            for item in raw['data']:
                if 'status' in item:
                    predicate = 'Status'
                    status = 'malicious' if item['status'] == -1 else 'safe' if item['status'] == 1 else 'undetermined'
                    level = 'malicious' if item['status'] == -1 else 'safe' if item['status'] == 1 else 'suspicious'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, f"{status}"))

                if 'risk_score' in item:
                    predicate = 'Risk'
                    risk_score = item['risk_score']
                    level = 'suspicious'
                    if risk_score <= self.risk_safe_limit:
                        level = 'safe'
                    elif self.risk_safe_limit < risk_score <= self.risk_sus_limit:
                        level = 'suspicious'
                    elif risk_score > self.risk_sus_limit:
                        level = 'malicious'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, f"{risk_score}"))

                if 'indicators' in item:
                    predicate = 'Block'
                    level = ''
                    umbrella_block = False
                    for i in item['indicators']:
                        if 'indicator' in i and i['indicator'] == 'Umbrella Block Status':
                            umbrella_block = i['score']
                            if umbrella_block:
                                level = 'malicious'
                            else:
                                level = 'safe'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, f"{umbrella_block}"))

        elif 'Samples' == self.service:
            for item in raw['data']:
                if 'records' in item and 'threatScore' in item['records']:
                    predicate = 'Threat'
                    threat_score = item['records']['threatScore']
                    level = 'suspicious'
                    if threat_score <= self.risk_safe_limit:
                        level = 'safe'
                    elif self.risk_safe_limit < threat_score <= self.risk_sus_limit:
                        level = 'suspicious'
                    elif threat_score > self.risk_sus_limit:
                        level = 'malicious'
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, f"{threat_score}"))
        else:
            data_count = 0
            predicate = 'RecordsCount'
            if self.service == 'report':
                for item in raw['data']:
                    if -1 != item['meta'].find('Summary'):
                        for i in item['data']:
                            data_count = data_count + i['total_hits']
            else:
                namespace = f'{self.service} Umbrella'
                data_count = len(raw['data'])

            taxonomies.append(self.build_taxonomy('info', namespace, predicate, data_count))

        return {'taxonomies': taxonomies}

    def run(self):
        data = self.get_param('data', None, 'Data is missing')

        if 'Investigate' == self.service:
            self.access_token = self.get_param('config.access_token', None, 'access_token is missing')
            response = self.run_umbrella_investigate(data)
            self.report(response)
        elif 'Samples' == self.service:
            self.access_token = self.get_param('config.access_token', None, 'access_token is missing')
            response = self.run_umbrella_samples(data)
            self.report(response)
        else:
            self.api_key = self.get_param('config.api_key', None, 'api_key is missing')
            self.api_secret = self.get_param('config.api_secret', None, 'api_secret is missing')
            self.organization_name = self.get_param('config.organization_name', None,
                                                    'organization_name is missing' if self.service != 'report' else None)
            self.organization_id = self.get_param('config.organization_id', None,
                                                  'organization_id is missing' if self.service != 'report' else None)
            self.query_limit = str(self.get_param('config.query_limit', 1000))
            if len(self.organization_name) == len(self.organization_id):
                self.organizations = dict(zip(self.organization_name, self.organization_id))
            else:
                self.error('Organization Names and IDs must be 1-to-1')
            if 'report' == self.service:
                combined_report = {'data': []}
                for key, value in self.organizations.items():
                    self.organization_id = value
                    report = self.run_umbrella_reports(data)
                    report['meta'] = key
                    combined_report['data'].append(report)

                summary = {'meta': 'Summary',
                           'data': []}
                dt_format = '%Y-%m-%d %H:%M:%S'
                for org in combined_report['data']:
                    org_name = org['meta']
                    org_data = {'organization': org_name}
                    ip_list = []
                    count = 0
                    ip_count = 0
                    dt_first = datetime.datetime.max
                    dt_last = datetime.datetime.min

                    for i_data in org['data']:
                        count = count + 1
                        ip = i_data['internalip']
                        if ip not in ip_list:
                            ip_list.append(ip)
                            ip_count = ip_count + 1
                        dt_first = min(dt_first,
                                       datetime.datetime.strptime(f'{i_data["date"]} {i_data["time"]}',
                                                                  dt_format))
                        dt_last = max(dt_last,
                                      datetime.datetime.strptime(f'{i_data["date"]} {i_data["time"]}',
                                                                 dt_format))

                    org_data['unique_ips'] = ip_count
                    org_data['total_hits'] = count
                    org_data['datetime_first'] = 'N/A' if len(org['data']) == 0 else dt_first.strftime(dt_format)
                    org_data['datetime_last'] = 'N/A' if len(org['data']) == 0 else dt_last.strftime(dt_format)
                    summary['data'].append(org_data)
                combined_report['data'].insert(0, summary)
                self.report(combined_report)
            else:
                response = self.run_umbrella_reports(data)
                self.report(response)


if __name__ == '__main__':
    UmbrellaAnalyzer().run()
