'''


Monumental thank you to Stephen Brannon for the original source code:

https://github.com/stephenbrannon/IOCextractor

I stand upon the shoulders of giants.

'''


#!/usr/bin/env python
# -*- coding: utf-8 -*-

#This script helps extract indicators of compromise (IOCs) from a text file.
#A user can add or remove tagged indicators then export the remaining tags.
#Usage: "python IOCextractor.py" or "python IOCextractor.py document.txt"
#2012 Stephen Brannon, Verizon RISK Team

from tkinter import *
from tkinter import filedialog
from tkinter import PhotoImage
from tkinter import Image

tags = ['md5', 'IPv4', 'url', 'Domain', 'email', 'file']

'''
domain and email regexes need work
'''

reMD5 = r"([A-F]|[0-9]){32}"
reIPv4 = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
reURL = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--" \
       r"11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--" \
       r"MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--" \
       r"YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--" \
       r"80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--" \
       r"S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--" \
       r"P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|" \
       r"|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC" \
       r"|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB" \
       r"|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP" \
       r"|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS" \
       r"|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO" \
       r"|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR" \
       r"|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)(/\S+)"
reDomain = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|" \
          r"XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|" \
          r"XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|" \
          r"XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|" \
          r"XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|" \
          r"XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO" \
          r"|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL" \
          r"|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG" \
          r"|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB" \
          r"|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM" \
          r"|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO" \
          r"|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS" \
          r"|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH" \
          r"|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"
reEmail = r"\b[A-Za-z0-9._%+-]+(@|\[@\])[A-Za-z0-9.-]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--" \
         r"HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|" \
         r"XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|" \
         r"XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|" \
         r"XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D" \
         r"|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|" \
         r"XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|" \
         r"XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|" \
         r"BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|" \
         r"FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|" \
         r"IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|" \
         r"ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|" \
         r"PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|" \
         r"SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|" \
         r"YE|YT|ZA|ZM|ZW)\b"
#reFile = r"[^\/:*?\"\<\>|].*.*\.(doc|jpg|csv|txt|exe|zip|xls|wpd|wp5|mid|midi|t65|psd|rtf|tar|txt|wk3|aiff|aif|bat|csk|dbf|eps|fm3|hqx|" \
#        r"jpg|jpeg|htm|html|mac|map|mdb|au|avi|bmp|class|java|cvs|dif|doc|exe|gif|mov|qt|mtb|mtw|pdf|p65|png|ppt|psp|" \
 #       r"qxd|ra|sit|tif|wav|wks)"

 ###Handling for test.txt and test[.]txt
reFile = r"[^\/:*?\"\<\>|]*\.\]+(doc|jpg|csv|txt|exe|zip|docm|xls|rtf|tar|txt|jpg|jpeg|htm|html|avi|bmp|class|php|java|cvs|exe|gif|pdf|png|ppt|tif|wav|wks)"

def dotToNum(ip): return int(''.join(["%02x"%int(i) for i in ip.split('.')]), 16)

def tag_initial():
   lines = text.get(1.0, 'end').split('\n')
   #md5
   text.tag_configure('md5', background='#FE6AA8')
   linenumber = 1
   for line in lines:
       for m in re.finditer(reMD5, line, re.IGNORECASE):
           text.tag_add('md5',str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
       linenumber += 1

   #ipv4
   text.tag_configure('IPv4', background='#00ffff')
   linenumber = 1
   for line in lines:
       for m in re.finditer(reIPv4, line, re.IGNORECASE):
           result = text.get(str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
           result = result.replace('[', '').replace(']', '') #remove brackets
           #reject private, link-local, and loopback IPs
           if result.find('10.') != 0 and \
              result.find('192.168') != 0 and \
              result.find('127') != 0:
               if (dotToNum(result) < dotToNum('172.16.0.0') or
                  dotToNum(result) > dotToNum('172.31.255.255')) and \
                  (dotToNum(result) < dotToNum('169.254.1.0') or
                  dotToNum(result) > dotToNum('169.254.254.255')):
                   text.tag_add('IPv4',str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
       linenumber += 1

   #domain
   text.tag_configure('Domain', background='#ff6600')
   linenumber = 1
   for line in lines:
       start = m.start()
       end = m.end()
       if '@' in line: #prevents email addresses with multiple '.' from being tagged twice
           pass
       else:
           for m in re.finditer(reDomain, line, re.IGNORECASE):
               if ' 'in m.string:
                   m.string.strip(' ')
               if ('http://' or 'https://') in m.string:
                   start = start - start
                   print('\n')
                   print(type(m.start))
                   print(m.string)
                   print('start: ', start)
                   print('end: ', end)
                   text.tag_add('Domain', str(linenumber) + '.' + str(start), str(linenumber) + '.' + str(m.end()))
               else:
                   #reject if preceding character is @ or following character is /
                   if not text.get(str(linenumber) + '.' + str(m.start()-1), str(linenumber) + '.' + str(m.start())) == '@':
                       if not text.get(str(linenumber) + '.' + str(m.end()), str(linenumber) + '.' + str(m.end()+1)) == '/':
                           text.tag_add('Domain', str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
       linenumber += 1

   #email
   text.tag_configure('email', background='#99ff66')
   linenumber = 1
   for line in lines:
       for m in re.finditer(reEmail, line, re.IGNORECASE):
           #reject known good emails
           result = text.get(str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
           if result.find('@verizon.com') == -1 and \
              result.find('@verizonbusiness.com') == -1 and \
              result.find('@fsisac.com') == -1 and \
              result.find('@one.verizon.com') == -1 and \
              result.find('@lists.fsisac.com')  == -1 and \
              result.find('@aexp.com') == -1 and \
              result.find('@swift.emsecure.net') == -1 and \
              result.find('@jp.verizonbusiness.com') == -1:
               text.tag_add('email', str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
       linenumber += 1

   #url
   text.tag_configure('url', background='#ccccff')
   linenumber = 1
   for line in lines:
       for m in re.finditer(reURL, line, re.IGNORECASE): #str(m.start()-m.start()) highlights the entire line to include protocol
           result = text.get(str(linenumber) + '.' + str(m.start()-m.start()), str(linenumber) + '.' + str(m.end()))
           stuff = result.split()
           if len(stuff) == 1:
               data = stuff[0]
           else:
               data = stuff[-1]
           end = len(data)
           start = (m.end()-len(data))
           #drop trailing punctuation
           while (u'.,\u201d"\'\u2019\\').find(data[len(data)-1:len(data)]) != -1:
               data = data[:len(data)-1]
               end -= 1
           #while (u'..\0020').find(data)
           if (u'\0020') in data:
               text.tag_add('url', str(linenumber) + '.' + str(start+1), str(linenumber) + '.' + str(start+end))
           else:
               text.tag_add('url', str(linenumber) + '.' + str(start), str(linenumber) + '.' + str(start+end))
       linenumber += 1

   #file
   text.tag_configure('file', background='#DAE0E6')
   linenumber = 1
   for line in lines:
       for m in re.finditer(reFile, line, re.IGNORECASE):
           result = text.get(str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
           stuff = result.split()
           if len(stuff) == 1:
               data = stuff[0]
           else:
               data = stuff[-1]
           end = len(data)
           start = (m.end()-len(data))
           while (u'.,\u201d"\'\u2019\\').find(data[len(data)-1:len(data)]) != -1:
               data = data[:len(data)-1]
               end -= 1
           if ('hxxp' or 'meow' or 'http') in data:
               pass
           else:
               text.tag_add('file', str(linenumber) + '.' + str(start), str(linenumber) + '.' + str(start+end))
       linenumber += 1


def askopen(filename = r''):
   print("Running IOC Extractor")
   if filename == '':
       print('\n', 'Target file: ', filename)
       filename = filedialog.askopenfilename(title="Select plain-text file",
                                         filetypes=[("txt file", ".txt"), ("All files", ".*")])
   if filename != '':
       print('\n', 'Target file: ', filename)
       with open(filename, 'rb') as f: #read as binary
           doc = f.read()
           doc = doc.decode('utf_8', 'ignore') #drop any non-ascii bytes

           #if a carriage return is orphaned, replace it with a new line
           doc = list(doc)
           i = 0
           while (i < len(doc) - 1):
               if ord(doc[i]) == 13: #it's a carriage return
                   if ord(doc[i + 1]) != 10: #it's not followed by a new line
                       doc[i] = chr(10) #replace it with a new line
               i += 1
           if ord(doc[len(doc)-1]) == 13: #end
               doc[len(doc)-1] = chr(10)

           #drop carriage returns
           i = 0
           while (i < len(doc) - 1):
               if ord(doc[i]) == 13: #it's a carriage return
                   doc.pop(i)
               else:
                   i += 1

           doc = ''.join(doc)
           text.delete('1.0',END)
           text.insert('1.0', doc)
           tag_initial()
           root.title(filename + ' - IOCextractor')

def clear_tag(holder=0):
   if len(text.tag_ranges("sel")) != 0: #selection is not empty
       #untag all occurrences of selected string
       key = text.get(text.tag_ranges("sel")[0], text.tag_ranges("sel")[1])
       lines = text.get(1.0, 'end').split('\n')
       linenumber = 1

       for line in lines:
           for m in re.finditer(re.escape(key), line, re.IGNORECASE):
               for t in tags:
                   text.tag_remove(t, str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
           linenumber += 1

       for t in tags: #necessary backup in case the regex fails to match
           text.tag_remove(t, text.tag_ranges("sel")[0], text.tag_ranges("sel")[1])

def tag_new(tag):
   if len(text.tag_ranges("sel")) != 0: #selection is not empty
       #remove any newline characters from the selection
       if '\n' in text.get(text.tag_ranges("sel")[0], text.tag_ranges("sel")[1]):
           line_start = (str(text.tag_ranges("sel")[0]).split('.'))[1]
           newline_index = text.get(text.tag_ranges("sel")[0], text.tag_ranges("sel")[1]).index('\n')
           del_line = str(text.tag_ranges("sel")[0]).split('.')[0]
           del_position = str(int(line_start) + int(newline_index))
           text.delete(del_line + '.' + del_position)

       #tag all occurences of selected string
       key = text.get(text.tag_ranges("sel")[0], text.tag_ranges("sel")[1])
       lines = text.get(1.0, 'end').split('\n')
       linenumber = 1
       for line in lines:
           for m in re.finditer(re.escape(key), line, re.IGNORECASE):
               for t in tags:
                   text.tag_add(tag, str(linenumber) + '.' + str(m.start()), str(linenumber) + '.' + str(m.end()))
           linenumber += 1

def export_csv():
   filename = filedialog.asksaveasfilename(title="Save As", filetypes=[("csv file", ".csv"), ("All files", ".*")])
   #filename = r'C:\Users\pp76508\Desktop\extractortest.csv'
   if filename != '':
       output = 'IOC,Type\n'
       #need better way to iterate through highlights and remove brackets
       for t in tags:
           indicators = []
           myhighlights = text.tag_ranges(t)
           mystart = 0
           for h in myhighlights:
               if mystart == 0:
                   mystart = h
               else:
                   mystop = h
                   if t == 'md5': #make all hashes uppercase
                       if not text.get(mystart, mystop).upper() in indicators:
                           indicators.append(text.get(mystart, mystop).upper())
                   else:
                       if not text.get(mystart, mystop).replace('[.]', '.').replace('[@]', '@') in indicators:
                           indicators.append(text.get(mystart, mystop).replace('[.]', '.').replace('[@]', '@'))
                   mystart = 0
           for i in indicators:
               if i.find(',') == -1: #no commas, print normally
                   output += str(i) + ',' + t + '\n'
               else: #internal comma, surround in double quotes
                   output += '"' + str(i) + '",' + t + '\n'
       if len(filename) - filename.find('.csv') != 4:
           filename += '.csv' #add .csv extension if missing
       with open(filename, 'w') as f:
           f.write(output)

root = Tk()
root.title('IOCextractor')

topframe = Frame(root)
topframe.pack()
bottomframe = Frame(root)
bottomframe.pack(side=BOTTOM)

openb = Button(topframe, text="Open File", command=askopen)
openb.pack(side=LEFT)

clear = Button(topframe, text="Clear", command=clear_tag)
clear.pack({"side": "left"})

md5 = Button(topframe, text="MD5", command=lambda: tag_new('md5'), bg="#FE6AA8")
md5.pack({"side": "left"})

IPv4 = Button(topframe, text="IPV4", command=lambda: tag_new('IPv4'), bg="#00ffff")
IPv4.pack({"side": "left"})

url = Button(topframe, text="URL", command=lambda: tag_new('url'), bg="#ccccff")
url.pack({"side": "left"})

domain = Button(topframe, text="Domain", command=lambda: tag_new('domain'), bg="#ff6600")
domain.pack({"side": "left"})

email = Button(topframe, text="Email", command=lambda: tag_new('email'), bg="#99ff66")
email.pack({"side": "left"})

file = Button(topframe, text="File", command=lambda: tag_new('file'), bg="#DAE0E6")
file.pack({"side": "left"})

export_csv = Button(topframe, text="Export CSV", command=export_csv)
export_csv.pack({"side": "left"})


#build main text area
text = Text(bottomframe, width=120, height=60)
text.pack({"side": "left"})
scrollbar = Scrollbar(bottomframe)
scrollbar.pack({"side": "left", "fill": "y"})
scrollbar.config(command=text.yview)
text.config(yscrollcommand=scrollbar.set)


text.bind('<Button-3>', clear_tag) #right-click selection to untag (Windows, Linux)
text.bind('<Command-Button-1>', clear_tag) #command-click selection to untag (Mac)

#insert doc if received as commandline argument
if len(sys.argv) == 2:
   askopen(sys.argv[1])

#output2 = export_csv

if __name__ == '__main__':
   root.mainloop()
   sys.exit()