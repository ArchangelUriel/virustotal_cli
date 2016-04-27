#!/usr/bin/python

import httplib
import urllib
import urllib2
import json
import time
import sys
import getopt
import hashlib
from parser import URLScanHtmlParser
from parser import FileScanHtmlParser
from collections import Counter

is_complete_output_requested = False

def show_analyzed_url_result(counter, results):
    
    global is_complete_output_requested

    header_and_footer = '+'+('-'*20)+"+"
    
    print header_and_footer
    print "|       RESULT       |"        
    print header_and_footer
    # Prints the compact result
    for element in counter:
        string_output = '| {0}: {1}'.format(element, counter[element])
        print "{0}{1}|".format(string_output,' '*((len(header_and_footer)-len(string_output))-1))
    print header_and_footer

    # Prints the detailed list result
    if is_complete_output_requested is True:
        header_and_footer = '+'+('-'*40)+"+"
        print header_and_footer
        print "|            DETAILED RESULTS            |"
        print header_and_footer
        for result in results:
            string_output = '|{0}: {1}'.format(result,results[result])
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
        result_counter = Counter(results.values())
        show_analyzed_url_result(result_counter, results)

def analyze_file(file_name):
    sha256_file = None
    json_data = None
    
    http_get_headers = {"Host":"www.virustotal.com",
                        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Encoding":"gzip, deflate, sdch",
                        "Accept-Language":"en-US,en;q=0.8,it;q=0.6",
                        "Connection":"close"
                       }
    sha256_file = hashlib.sha256(open(file_name,'rb').read()).hexdigest()
    http_request = httplib.HTTPSConnection("www.virustotal.com")
    http_request.request("GET","/it/file/upload/?sha256={0}".format(sha256_file))
    json_data = http_request.getresponse().read()
    print json_data    
  
    if json_data is not None:
        json_object = json.loads(json_data)
        file_exists = json_object['file_exists']
        last_analysis_url = str(json_object['last_analysis_url'])
        reanalyse_url = str(json_object['reanalyse_url'])
        print reanalyse_url
        if file_exists == True:
            http_get_headers['GET'] = last_analysis_url
            http_request = urllib2.Request("https://www.virustotal.com{0}".format(last_analysis_url), None, http_get_headers)
            html_data = urllib2.urlopen(http_request).read()
            parser = FileScanHtmlParser()
            results = parser.get_results()
            result_counter = Counter(results.values())
            print results
        else:
            http_get_headers['GET'] = last_analysis_url
            http_request = urllib2.Request("https://www.virustotal.com{0}".format(reanalyse_url),None,http_get_headers)
            http_data = urllib2.urlopen(http_request).read()
            #print http_data
            parser = FileScanHtmlParser()
            results = parser.get_results()
            result_counter = Counter(results.values())
            print results
    

def main(argv):
   
    global is_complete_output_requested 
    url_to_be_analyzed = None
    file_to_be_analyzed = None

    try:
        opts, args = getopt.getopt(argv,"hu:f:v",["url=","file="])
    except getopt.GetoptError:
        print "Invalid Argument, type virustotal.py -h"
        sys.exit(2)
   
    for opt, arg in opts:
        if opt == "-h":
            print "Print Help"
            sys.exit()
        elif opt in ("-u","--url"):
            url_to_be_analyzed = arg
        elif opt in ("-f","--file"):
            file_to_be_analyzed = arg
        elif opt  == "-v":
            is_complete_output_requested = True
       
    
    if url_to_be_analyzed != None:
        analyze_url(url_to_be_analyzed)
    if file_to_be_analyzed != None:
        analyze_file(file_to_be_analyzed)

if __name__ == '__main__':
    main(sys.argv[1:])
