import os,sys,textwrap

def color(string,color=None):
    attr = []
    attr.append('1')
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

def wrap_columns(col1,col2,width1=24,width2=40,indent=31):
    lines1 = textwrap.wrap(textwrap.dedent(col1).strip(),width=width1)
    lines2 = textwrap.wrap(textwrap.dedent(col2).strip(),width=width2)
    result = ''
    limit = max(len(lines1),len(lines2))
    for x in xrange(limit):
        if x < len(lines1):
            if x != 0:
                result += ' ' * indent
            result += '{line: <0{width}s}'.format(width=width1,line=lines1[x])
        else:
            if x == 0:
                result += ' ' * width1
            else:
                result += ' ' * (indent + width1)
        if x < len(lines2):
            result += '  ' + '{line: <0{width}s}'.format(width=width2,line=lines2[x])
        if x != limit-1:
            result += "\n"
    return result

def display_module(moduleName,module):
    if module.info:
        print '\n{0: >15}'.format("Name: ") + str(module.info['Name'])
        print '{0: >15}'.format("Module: ") + str(moduleName)
        print '{0: >15}'.format('Authors: ')+str(module.info['Author'])
        print '{0: >15}'.format('Description: ')+str(module.info['Description'])
        print '{0: >15}'.format('Comments: ')+str(module.info['Comments'])
    if module.options:
        x=len(max(module.options.keys(),key=len))
        print "\nOptions:\n"
        print "  %sRequired    Value                     Description" %('{:<{}s}'.format("Name", x+1))
        print "  %s--------    -------                   -----------" %('{:<{}s}'.format("----", x+1))
        for key,value in module.options.iteritems():
            str1='{:<{}s}'.format(str(key),x+1)
            str2='{0: <12}'.format("True" if value['Required'] else "False")
            str3=wrap_columns(str(value['Value']),str(value['Description']),indent=31+x-16)
            print "  %s%s%s\n" % (str1,str2,str3)




