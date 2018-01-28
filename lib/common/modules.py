import os,sys,imp,fnmatch,cmd
import helpers

class Exploit(cmd.Cmd):
    def __init__(self,Main,moduleName):
        cmd.Cmd.__init__(self)
        self.doc_header = 'Exploit Commands'
        self.main=Main
        self.moduleName=moduleName
        self.exploit=Main.modules.modules[moduleName]
        self.prompt = '(Exploit: ' + helpers.color(self.moduleName, color="blue") + ') > '

    def default(self,line):
        pass

    def do_back(self,line):
        return True

    def do_main(self,line):
        raise KeyboardInterrupt

    def do_info(self,line):
        helpers.display_module(self.moduleName,self.exploit)

    def do_set(self,line):
        parts=line.split()
        try:
            if parts[0] not in self.exploit.options:
                print helpers.color("[!] Invalid option specified")
            else:
                value=' '.join(parts[1:])
                if value == '""' or value == "''":
                    value = ""
                self.exploit.options[parts[0]]['Value'] = value
        except:
            print helpers.color("[!] Error in setting option, likely invalid option name")

    def complete_set(self,text,line,begidx,endidx):
        keys=self.exploit.options.keys()
        mline=line.partition(' ')[2]
        offs=len(mline)-len(text)
        return [s[offs:] for s in keys if s.lower().startswith(mline.lower())]

    def do_check(self,line):
        if self.exploit.check():
            print helpers.color("[!] Website Vulnerable.")
        else:
            print helpers.color("[*] Website Safe.")

    def do_exploit(self,line):
        if len(line)<1:
            print helpers.color("[!] please input cmd")
        else:
            ret=self.exploit.exploit(line)
            print helpers.color(ret)

class Modules:
    def __init__(self,Main):
        self.main=Main
        self.modules={}
        self.load_modules()

    def load_modules(self):
        ext='*.py'
        dir=sys.path[0]+'/lib/modules'
        for root,dirs,files in os.walk(dir):
            for filename in fnmatch.filter(files,ext):
                path=os.path.join(root,filename)
                moduleName = path.split(dir)[-1][0:-3][1:]
                self.modules[moduleName]=imp.load_source(moduleName,path).Module(self.main)
