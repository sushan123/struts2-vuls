import os,sys,cmd,time
import modules
import helpers

VERSION = "0.1"

class Main(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = '(vulScan) > '
        self.doc_header = 'Commands'
        self.modules = modules.Modules(self)

    def cmdloop(self):
        while 1==1:
            try:
                xx=self.modules.modules
                if xx:
                    xx=len(xx)
                else:
                    xx=0
                print '       '+helpers.color(str(xx),"red")+' modules currently loaded\n'
                cmd.Cmd.cmdloop(self)
            except KeyboardInterrupt as e:
                return True
            except Exception as e:
                time.sleep(3)

    def default(self,line):
        pass

    def do_exit(self,line):
        raise KeyboardInterrupt

    def do_search(self,line):
        line=line.strip().lower()
        for name,module in self.modules.modules.iteritems():
            if line=='' or line in name.lower():
                print " %s\n" % (helpers.color(name,'blue'))

    def do_usemodule(self,line):
        name=line.strip()
        if name not in self.modules.modules:
            print helpers.color('[!] Error: invalid module')
        else:
            try:
                exp=modules.Exploit(self,name)
                exp.cmdloop()
            except:
                pass
  
    def complete_usemodule(self,text,line,begidx,endidx):
        names=self.modules.modules.keys()
        mline=line.partition(' ')[2]
        offs=len(mline)-len(text)
        ret=[s[offs:] for s in names if s.startswith(mline)]
        return ret

    def do_interact(self,line):
        name=line.strip()
        print line

    
