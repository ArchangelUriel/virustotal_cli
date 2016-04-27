from HTMLParser import HTMLParser

'''
Url Scan Html Parser
'''
class URLScanHtmlParser(HTMLParser):
    last_tag = None
    last_attr = None
    last_element = None
    is_data_found = False
    data_index = 0
    temp_website = None
    temp_rating = None
    results = {}
    
    def handle_starttag(self, tag, attrs):
        self.last_tag = tag
        self.last_attr = attrs

    def handle_data(self, data):
        if  self.is_data_found == False:
            if self.last_tag == "table":
                if self.last_attr[1][1] == 'scanning-results':
                    self.is_data_found = True

        else:
            if self.last_tag == 'td':
                stripped_data = data.strip()
                if stripped_data is not "" :
                    if (self.data_index % 2) == 0:
                        self.temp_website = data
                    else:
                        self.temp_rating = data
                        self.results[self.temp_website] = self.temp_rating
                        self.temp_website = None
                        self.temp_rating = None
                    self.data_index+=1

    def get_results(self):
        return self.results


'''
File Scan Html Parser
'''
class FileScanHtmlParser(HTMLParser):
   last_tag = None
   last_attr = None
   last_element = None
   is_data_found = False
   data_index = 0
   temp_av = None
   temp_scan_result = None
   results = {}
   
   def handle_starttag(self, tag, attrs):
       self.last_tag = tag
       self.last_attr = attrs
 
   def handle_data(self, data):
       if  self.is_data_found == False:
           if self.last_tag == "table" and len(self.last_attr) > 1:
               if self.last_attr[1][1] == 'antivirus-results':
                   self.is_data_found = True
 
       elif self.last_tag == 'td':
               if self.last_attr[0][1] == 'ltr' and (self.data_index % 2) == 0:
                   stripped_data = data.strip()
                   if stripped_data is not "" :
                       print stripped_data, self.data_index
                       self.temp_av = stripped_data
               self.data_index += 1
 
       elif self.last_tag == 'i':
           if self.temp_av is not None:
               self.temp_scan_result = self.last_attr[1][1].strip()
               self.results[self.temp_av] = self.temp_scan_result
 
               self.temp_av = None
               self.temp_scan_result = None
           
 
   def get_results(self):
       return self.results
 
