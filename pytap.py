# pytap.py
#
# Library to query the Proofpoint TAP API for information on click events, VAPs, IOCs, and campaign data
#
# github.com/jasonsford
# 3 August 2022

import json
import requests

class pytap:

    def __init__(self):

        self.tap_base_url = 'https://tap-api-v2.proofpoint.com/v2'

        # The Auth Token is generated in the Settings tab of the TAP dashboard. Click on "Connected Applications" and then select "Create New Credential".

        self.tap_token = ('your TAP service principal', 'your TAP service secret')

        # Data format specifies the format in which data is returned. If no format is specified, syslog will be used as the default. 
        
        self.tap_data_format = '?format=json'
        
        # sinceSeconds is an integer representing a time window in seconds from the current API server time. The start of the window is the current API server time,
        # rounded to the nearest minute, less the number of seconds provided. The end of the window is the current API server time rounded to the nearest minute. 
        # If json output is selected, the end time is included in the returned result.

        self.tap_time_format = '&sinceSeconds=3600'

    def tap_campaign(self, identifier:str):

        # TAP CAMPAIGN API - https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API
        # The Campaign API allows administrators to pull specific details about campaigns, including: 
        # - Description
        # - Actor, malware family, and techniques associated with the campaign
        # - Threat variants which have been associated with the campaign

        request_url = self.tap_base_url + '/campaign/' + identifier

        response = requests.get(request_url, auth=(self.tap_token))

        print(json.dumps(response.json(), indent=4, separators=(',', ': ')))

    def tap_forensics(self, identifier:str):

        # TAP FORENSICS API - https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Forensics_API
        # The Forensics API allows administrators to pull detailed forensic evidences about individual threats or campaigns observed in their environment. 
        # These evidences could be used as indicators of compromise to confirm infection on a host, as supplementary data to enrich and correlate against other 
        # security intelligence sources, or to orchestrate updates to security endpoints to prevent exposure and infection.

        threatid = '?threatId=' + identifier

        request_url = self.tap_base_url + '/forensics' + threatid

        response = requests.get(request_url, auth=(self.tap_token))

        print(json.dumps(response.json(), indent=4, separators=(',', ': ')))

    def tap_people(self, window:str):

        # TAP PEOPLE API - https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/People_API
        # The People API allows administrators to identify which users in their organizations were most attacked during a specified period.
        # All timestamps in the returned events are in UTC and provided in JSON format.

        people_window = '?window=' + window

        request_url = self.tap_base_url + '/people/vap' + people_window

        response = requests.get(request_url, auth=(self.tap_token))

        print(json.dumps(response.json(), indent=4, separators=(',', ': ')))

    def tap_threat(self, identifier:str):

        # TAP THREAT API - https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Threat_API
        # The Threat API allows administrators to pull detailed attributes about individual threats observed in their environment.
        # It can be used to retrieve more intelligence for threats identified in the SIEM or Campaign API responses.

        request_url = self.tap_base_url + '/threat/summary/' + identifier

        response = requests.get(request_url, auth=(self.tap_token))

        print(json.dumps(response.json(), indent=4, separators=(',', ': ')))

    def tap_siem(self, endpoint:str):

        # TAP SIEM API - https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
        # The API allows integration with these solutions by giving administrators the ability to periodically download detailed information about several types of 
        # TAP events in a SIEM-compatible, vendor-neutral format. Currently, the following event types are exposed:
        #	1. Blocked or permitted clicks to threats recognized by URL Defense
        #	2. Blocked or delivered messages that contain threats recognized by URL Defense or Attachment Defense

        siem_endpoints = ['/siem/clicks/blocked', 
						'/siem/clicks/permitted', 
						'/siem/clicks/messages/blocked',
						'/siem/clicks/messages/delivered',
						'/siem/issues',
						'/siem/all']

        request_url = self.tap_base_url + siem_endpoints[int(endpoint)] + self.tap_data_format + self.tap_time_format

        response = requests.get(request_url, auth=(self.tap_token))

        print(json.dumps(response.json(), indent=4, separators=(',', ': ')))