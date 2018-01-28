#coding:utf-8

import os,sys,requests,urlparse
import helpers

reload(sys)
sys.setdefaultencoding('utf-8')

class Http:
    def __init__(self,Options={}):
        self.options=Options
        self.header={'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36'}
        self.url=self.options['URL']['Value']
        if len(self.url)<5:
            self.url=self.options['RHOST']['Value']+':'+self.options['RPORT']['Value']+'/'+self.options['URIPATH']['Value']
        if not self.url.lower().startswith('http://'):
            self.url='http://'+self.url

    def get(self,header,times=30):
        try:
            return requests.get(self.url, headers=dict(self.header,**header), timeout=times, verify=False,allow_redirects=False)
        except:
            return None

    def post(self,header,datas,times=30):
        try:
            return requests.post(self.url, headers=dict(self.header,**header), data=datas, timeout=times, verify=False,allow_redirects=False)
        except:
            return None
