#!/usr/bin/env python

'''
GrabberZ is a small python script which is capable of extracting metadata from different file types, downloaded from search engines.
Only google hack has been implemented, atm.

The purpose of coding this little script was to be able to gather as much information as possible
from a domain name during the reco/enu pentest step.
'''

__author__ = "v4lproik"
__date__ = "01/29/2013"
__version__ = "1.0"
__maintainer__ = "v4lproik"
__email__ = "v4lproik@gmail.com"
__status__ = "Development"


try:
    import traceback
    import sys
    import urlparse
    import ConfigParser
    import argparse
    from BeautifulSoup import BeautifulSoup
    import urllib2
    import re
    import string
    import hashlib
    import uuid
    import time
    import math
    import random
    import os
    import lib.PyPDF2 as pyPdf
    import socks
    import socket
    from hachoir_core.error import error, HachoirError
    from hachoir_core.cmd_line import unicodeFilename
    from hachoir_core.i18n import getTerminalCharset, _
    from hachoir_core.benchmark import Benchmark
    from hachoir_core.stream import InputStreamError
    from hachoir_core.tools import makePrintable
    from hachoir_parser import createParser, ParserList
    import hachoir_core.config as hachoir_config
    from hachoir_metadata import config
    from optparse import OptionGroup, OptionParser
    from hachoir_metadata import extractMetadata
    from hachoir_metadata.metadata import extractors as metadata_extractors

except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    print >>sys.stderr, "[X] You need to install the following packages in order to run this tool \npython-beautifulsoup\npython-hachoir-core\npython-hachoir-parser\npython-hachoir-metadata"
    sys.exit(1)

'''
Default variables
'''
global limit
limit = 100

global md5_dic
md5_dic = {}


def banner():
    banner = '''
	|----------------------------------------------------------|
	|                        GrabberZ  1.0                     |
	|                           V4lproik                       |
	|----------------------------------------------------------|\n'''
    print banner


def getResult(domain, type):
    url = "https://www.google.fr/search?hl=en&q=site%3A" + domain + \
        "+filetype%3A" + type + "&oq=site%3A" + domain + "+filetype%3A" + type
    # print url
    req = urllib2.Request(url, headers={'User-Agent':
                          "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6"})
    data = urllib2.urlopen(req)

    page = data.read()

    soup = BeautifulSoup(page)
    resulta = soup.find("div", {"id": "resultStats"})
    resulta = str(resulta)

    results = re.sub("\D", "", resulta)

    try:
        return int(results)
    except:
        return 0


def scan(domain, type, path, i):
    url = "https://www.google.fr/search?hl=en&q=site%3A" + domain + "+filetype%3A" + type + \
        "&oq=site%3A" + domain + "+filetype%3A" + type + "&start=" + str(i)
    req = urllib2.Request(url, headers={'User-Agent':
                          "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6"})
    data = urllib2.urlopen(req)

    page = data.read()
    # Link Extraction
    soup = BeautifulSoup(page)
    links = soup.findAll('a', href=True)
    if(len(links) > 0):
        for link in links:
            pattern = r'(.*)\.' + type + '(\.*)'
            if(re.search(pattern, link['href'])):
                # print link['href']
                print "------------------------------------------------------------------------"
                if(link['href'].startswith('/webcache') or link['href'].startswith('//webcache')):
                    if(re.findall(r'http://(.*?)\.' + type, link['href'])):
                        url = "http://" + re.findall(
                            r'http://(.*?)\.' + type, link['href'])[0] + "." + type
                    elif (re.findall(r'http://(.*?)\.' + type, link['href'])):
                        url = "https://" + re.findall(
                            r'https://(.*?)\.' + type, link['href'])[0] + "." + type

                    filename = link['href'].split("q=")[1].split("%2B")[0]
                    listname = filename.split('/')
                    filename = listname[len(listname) - 1]

                else:
                    url = "https://google.fr" + link['href']
                    filename = link['href'].split("q=")[1].split("&")[0]
                    listname = filename.split('/')
                    filename = listname[len(listname) - 1]

                # print hashfile(path + "/" filename)
                # print url
                req = urllib2.Request(url, headers={'User-Agent':
                                      "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6"})

                try:
                    f = urllib2.urlopen(req)
                    data = f.read()
                    addr = socket.gethostbyname(urlparse.urlparse(f.geturl()).netloc)
                    f.close()
                except urllib2.URLError, e:
                    print "Not able to find the file at " + addr
                else:
                    # don't wanna rename a file... bool
                    compute = False
                    filePath = path + "/" + filename
                    global md5_dic

                    if(checkIfFileExist(filePath)):
                        print "[X] File already exists: " + filePath

                        # save the to compute an md5 checksum
                        filePathExist = filePath
                        filePath = re.sub("." + type, '', filePath)
                        filePath = filePath + "_" + getUniqid() + "." + type
                        saveFile(filePath, data)

                        # check if there is an entry in the table for this
                        # checksum
                        md5OfPathFile = md5Checksum(filePath)
                        hashFilePath = md5_dic.get(md5OfPathFile, False)
                        if(hashFilePath):
                            print "[X] The file " + filePathExist + " has already been analyzed."
                        elif(md5Checksum(filePath) == md5Checksum(filePathExist)):
                            print "[X] The file " + filePathExist + " has already been downloaded but not analyzed."
                            # rollback delete file
                            os.remove(filePath)

                            # save in the table
                            md5_dic[md5OfPathFile] = filePathExist
                            compute = True
                            filePath = filePathExist
                        else:
                            saveFile(filePath, data)
                            md5_dic[md5OfPathFile] = filePath
                            print "[*] The file " + filePath + " has been saved with the following md5 checksum : " + md5OfPathFile
                            compute = True
                    else:
                        saveFile(filePath, data)
                        md5OfPathFile = md5Checksum(filePath)
                        md5_dic[md5OfPathFile] = filePath
                        print "[*] The file " + filePath + " has been saved with the following md5 checksum : " + md5OfPathFile
                        compute = True

                if(compute):
                    print "[*] File " + filePath + " from " + addr
                    if(type == "pdf"):
                        getMetaDataPdf(filePath, type)
                    else:
                        valuesT = {
                            'quality': 1, 'level': '9', 'mime': False, 'debug': False,
                            'profiler': False, 'type': False, "force_parser": None}
                        getMetaDataOther(valuesT, filePath)
    else:
        print "[X] No Links have been found..."


def saveFile(filePath, data):
    FILE = open(filePath, "wb")
    FILE.write(data)
    FILE.close()


def checkIfFileExist(filePath):
    try:
        with open(filePath) as f:
            pass
    except IOError as e:
        return False
    return True


def md5Checksum(filePath):
    md5 = hashlib.md5()
    with open(filePath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), ''):
            md5.update(chunk)
    return md5.hexdigest()


def checkArgs():
    if len(sys.argv) < 7:
        # usage()
        parser.print_help()
        sys.exit()


def getUniqid():
    m = time.time()
    uniqid = '%8x%05x' % (math.floor(m), (m - math.floor(m)) * 1000000)
    return uniqid


def getMetaDataPdf(filePath, type):
    # print filePath
    flag = True
    try:
        pdf = pyPdf.PdfFileReader(open(filePath, 'rb'))
        if not pdf.isEncrypted:
            for key in pdf.documentInfo:
                print key.encode('utf-8') + ": " + str(pdf.documentInfo[key].encode('utf-8'))
        else:
            if(pdf.getIsEncrypted()):
                if(pdf.decrypt("") == 1):
                    for key in pdf.documentInfo:
                        print key.encode('utf-8') + ": " + str(pdf.documentInfo[key].encode('utf-8'))
                else:
                    print "[X] Not able to recover information due to a decryption failed."
                    flag = False
            else:
                print "Not Able to find the password..."
                flag = False

        if(flag):
            content = getPDFContent(pdf)
            emails = get_email(content)
            if emails:
                print "Emails found : "
                for email in emails:
                    print "	- " + email
            macs = get_mac(filePath)
            if macs:
                print "Mac addresses found : "
                for mac in macs:
                    print "	- " + mac
            ips = get_ip(content)
            if macs:
                print "Ip addresses found : "
                for ip in ips:
                    print "	- " + ip
    except IOError as e:
        print "File can't be read..."
    except:
        pass

'''
	This function has been taken from metagoofil. All credits belong to his owner .
'''


def get_mac(filePath):
    line = open(filePath, 'r')
    res = ""
    for l in line:
        res += l
    macrex = re.compile('-[0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z][0-9a-zA-Z]\}')
    macgetter = macrex.findall(res)
    if macgetter == []:
        mac = ''
    else:
        mac = macgetter[0]
        mac = mac.strip("-")
        mac = mac.strip("}")
        mac = mac[:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + \
            mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
    return mac


def get_email(content):
    emails = re.findall(r'[\w.-]+@[\w.-]+', content)
    return emails


def get_ip(content):
    ips = re.match(r'[0-9]+(?:\.[0-9]+){3}', content)
    return ips


def getMetaDataOther(values, filename, display_filename=False, priority=None, human=True, display=True, charset='utf-8'):
    real_filename = filename

    # Create parser
    try:
        if values['force_parser']:
            tags = [("id", values['force_parser']), None]
        else:
            tags = None
        parser = createParser(filename, real_filename=real_filename, tags=tags)
    except InputStreamError, err:
        error(unicode(err))
        return False
    if not parser:
        error(_("Unable to parse file: %s") % filename)
        return False

    extract_metadata = not(values['mime'] or values['type'])
    if extract_metadata:
        try:
            metadata = extractMetadata(parser, values['quality'])
        except HachoirError, err:
            error(unicode(err))
            metadata = None
        if not metadata:
            parser.error(_("Hachoir can't extract metadata, but is able to parse: %s")
                         % filename)
            return False

    if display:
        if extract_metadata:
            text = metadata.exportPlaintext(priority=priority, human=human)
            if not text:
                text = [_("(no metadata, priority may be too small)")]
            if display_filename:
                for line in text:
                    line = "%s: %s" % (filename, line)
                    print makePrintable(line, charset)
            else:
                for line in text:
                    print makePrintable(line, charset)
        else:
            if values.type:
                text = parser.description
            else:
                text = parser.mime_type
            if display_filename:
                text = "%s: %s" % (filename, text)
            print text
    return True


def getPDFContent(pdf):
    content = ""
    num_pages = 10
    num_pages = pdf.getNumPages()
    for i in range(0, num_pages):
        content += pdf.getPage(i).extractText() + "\n"
    # content = " ".join(content.replace(u"\xa0", " ").strip().split())
    return content


def cleanPath(path):
    if(path[-1:] == "/"):
        return path[0:len(path) - 1]
    else:
        return path


def setProxySockConf(host, port):
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port)
    socket.socket = socks.socksocket

if __name__ == "__main__":
    banner()
    try:
        parser = argparse.ArgumentParser()
        gr1 = parser.add_argument_group("Main arguments")
        gr1.add_argument('-d', '--domain', dest='domain',
                         required=True, help='Domain to check')
        gr1.add_argument('-t', '--type', dest='type',
                         required=True, help='File types\' pdf, ppt, pptx...')
        gr1.add_argument('-p', '--path', dest='path', required=True,
                         help='Directory where found files are stored (Need Read/Written permissions)')

        gr2 = parser.add_argument_group("Other arguments")
        gr2.add_argument('-l', '--limit', dest='limit',
                         help='limit results from engine search', default=100, type=int)
        gr2.add_argument('-s', '--socks', dest='socks',
                         help='use a proxy type sock (ex: 127.0.0.1:5678)', default=False)
        gr2.add_argument('-o', '--output', dest='output',
                         help='output in file .html', default=False)

        checkArgs()

        args = parser.parse_args()

        # test permission within the given folder
        path = cleanPath(args.path)
        saveFile(path + "/" + "test.txt", "test")

        # store limit
        limit = args.limit
        save_limit = limit

        # get all extensions
        typesF = args.type.split(",")

        try:
            tmp = args.socks.split(':')
            setProxySockConf(tmp[0], int(tmp[1]))
        except:
            pass

        for typeF in typesF:
            typeF = re.sub(" ", "", typeF)
            result = getResult(args.domain, typeF)

            if(result > 0):
                if(result < limit):
                    limit = result

                print "[*] " + str(result) + " result(s) have been found for the type : " + typeF + "\n"

                for i in xrange(0, limit, 10):
                    scan(args.domain, typeF, path, i)
            else:
                print "\n[X] No " + typeF + " found for the domain : " + args.domain + "\n"
                if(typesF[len(typesF) - 1] == typeF):
                    print "\nProgram Exit...\n"
    except KeyboardInterrupt:
        print "Process interrupted by user.."
    # except Exception as value:
    #     print str(value) + "\n"
    except:
    	print "\n\n\n\n", traceback.format_exc()
