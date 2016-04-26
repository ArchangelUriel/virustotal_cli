#!/usr/bin/python

import httplib
import urllib
import json
import time
import sys
import getopt
from parser import URLScanHtmlParser
from collections import Counter

def show_analyzed_url_result(counter):
    
    header_and_footer = '+'+('-'*20)+"+"
    
    print header_and_footer
    header_and_footer = '+'+('-'*20)+"+"
    print "|       RESULT       |"        
    print header_and_footer
    for element in counter:
        string_output = '| {0}: {1}'.format(element, counter[element])
        print "{0}{1}|".format(string_output,' '*((len(header_and_footer)-len(string_output))-1))
    print header_and_footer

def analyze_url(url):
    
    sh256_link = None
    timestamp_link = None
    last_analysis_link = None
    json_data = None

    http_post_params = urllib.urlencode({'url': url})
    http_post_headers = {"origin":'https://www.virustotal.com',
                         "referer": "https://www.virustotal.com/it/",
                         "Content-type": "application/x-www-form-urlencoded",
                         "Accept": "application/json, text/javascript, */*; q=0.01"}
    
    http_request = httplib.HTTPSConnection("www.virustotal.com")    
    http_request.request("POST","/it/url/submission/", http_post_params, http_post_headers)
    json_data = http_request.getresponse().read()

    if json_data is not None:
        json_object = json.loads(json_data)
        sha256_link = json_object['sha256']
        timestamp_link = json_object['timestamp']
        last_analysis_link = json_object['last_analysis_url']

    
        http_request.request("GET", last_analysis_link)
        
        html_data_response = http_request.getresponse().read() 
        parser = URLScanHtmlParser()
        parser.feed(html_data_response)
        results = parser.get_results()
        #for result in results:
            #print "{0}: {1}".format(result, results[result]) 
        result_counter = Counter(results.values())
    show_analyzed_url_result(result_counter)
def main(argv):
    
    url_to_be_analyzed = None

    try:
        opts, args = getopt.getopt(argv,"hu:",["url="])
    except getopt.GetoptError:
        print "Invalid Argument, type virustotal.py -h"
        sys.exit(2)
   
    for opt, arg in opts:
        if opt == "-h":
            print "Print Help"
            sys.exit()
        elif opt in ("-u","--url"):
            url_to_be_analyzed = arg
    
    if url_to_be_analyzed != None:
        analyze_url(url_to_be_analyzed)

if __name__ == '__main__':
    main(sys.argv[1:])
