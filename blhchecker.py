from burp import IBurpExtender,IScannerCheck,IScanIssue
from array import array
import re,threading,ssl
try:
	import Queue as queue
except:
	import queue as queue
import urllib3
urllib3.disable_warnings()

#REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
regex_str = r"""
  (?:"|')                               # Start newline delimiter
  (
	((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	[^"'/]{1,}\.                        # Match a domainname (any character + dot)
	[a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	|
	((?:/|\.\./|\./)                    # Start with /,../,./
	[^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	[^"'><,;|()]{1,})                   # Rest of the characters can't be
	|
	([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	[a-zA-Z0-9_\-/]{1,}                 # Resource name
	\.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	(?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	|
	([a-zA-Z0-9_\-]{1,}                 # filename
	\.(?:php|asp|aspx|jsp|json|
		 action|html|js|txt|xml)             # . + extension
	(?:\?[^"|']{0,}|))                  # ? mark with parameters
  )
  (?:"|')                               # End newline delimiter
"""


http = urllib3.PoolManager()

ISSUE_FORMAT = '''CustomScanIssue(baseRequestResponse.getHttpService(),self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
	[self._callbacks.applyMarkers(baseRequestResponse,None,None)],"Broken Link Hijacking","The Response contains the url : {0}","Low")'''

class BurpExtender(IBurpExtender,IScannerCheck):
	extension_name = "Broken Link Hijacking"
	q = queue.Queue()
	def registerExtenderCallbacks(self,callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self._callbacks.setExtensionName(self.extension_name)
		callbacks.registerScannerCheck(self)


	# def split(self,strng, sep, pos):
	# 	strng = strng.split(sep)
	# 	return sep.join(strng[:pos]), sep.join(strng[pos:])

	def _up_check(self,url):
		try:
			r = http.request('GET',url,redirect=True,timeout=5)
			return url,r.status == 200
		except Exception as e:
			print("Exception for : "+str(url)+" => "+str(e))
			return url,False

	# def process_queue(self,res):
	# 	while not self.q.empty():
	# 		try:
	# 			url = self.q.get()
	# 			furl,code = self._up_check(str(url))
	# 			if code == False:
	# 				matches.append(furl)
	# 				#self._processIssue(furl,res)
	# 		except Exception:
	# 			pass
				

	# def _blf(self,baseRequestResponse,regex,host):
	# 	pass


	def doPassiveScan(self,baseRequestResponse):
		_HTTP = baseRequestResponse.getHttpService()
		res = self._helpers.bytesToString(baseRequestResponse.getResponse())
		_host = str(_HTTP.getProtocol())+"://"+str(_HTTP.getHost())
		regex = re.compile(regex_str,re.VERBOSE)
		re_r = regex.findall(res)
		if len(re_r) == 0:
			return
		re_r = list(set([tuple(j for j in re_r if j)[-1] for re_r in re_r]))
		re_r = [i.encode('utf-8').strip('') for i in re_r]
		re_r = [i.replace('\\','/') for i in re_r]
		final = []
		for i in re_r:
			if i.startswith('/') and ' ' not in i:
				i = str(_host)+str(i)
				final.append(i)
			elif i.startswith('http') or i.startswith('www.'):
				final.append(i)
		for i in final:
			url,code = self._up_check(str(i))
			if code == False:
				issue = ISSUE_FORMAT.format(str(url))
				self._callbacks.addScanIssue(eval(issue))
		print('DONE')


	def consolidateDuplicateIssues(self,existingIssue,newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			print('MADARJAT')
			return -1
		return 0
		print('WOOT')


class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity

	def getUrl(self):
		return self._url

	def getIssueName(self):
		return self._name

	def getIssueType(self):
		return 0

	def getSeverity(self):
		return self._severity

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		pass

	def getRemediationBackground(self):
		pass

	def getIssueDetail(self):
		return self._detail

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
