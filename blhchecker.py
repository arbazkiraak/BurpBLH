from burp import IBurpExtender,IScannerCheck,IScanIssue,IHttpService
from array import array
import re,threading
try:
	import Queue as queue
except:
	import queue as queue
from java.net import URL
import urlparse
from java.io import PrintWriter
from java.lang import RuntimeException

## FOR URL BASED, Use below regex
#REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

## LINK BASED REGEX FOR HTML
regex_str = r'(href|src|icon|data|url)=[\'"]?([^\'" >;]+)'


WHITELIST_CODES = [200]
WHITELIST_PATTERN = ["/","../","http","www"]
WHITELIST_MEMES = ['HTML','Script','Other text','CSS','JSON']

class BurpExtender(IBurpExtender,IScannerCheck):
	extension_name = "Link Hijacking"
	q = queue.Queue()
	temp_urls = []
	no_of_threads = 15
	def registerExtenderCallbacks(self,callbacks):
		try:
			self._callbacks = callbacks
			self._helpers = callbacks.getHelpers()
			self._callbacks.setExtensionName(self.extension_name)
			self._stdout = PrintWriter(self._callbacks.getStdout(),True)
			self._stderr = PrintWriter(self._callbacks.getStderr(),True)
			callbacks.registerScannerCheck(self)
			self._stdout.println("Extension Successfully Installed")
			return
		except Exception as e:
			self._stderr.println("Installation Problem ?")
			self._stderr.println(str(e))
			return

	def split(self,strng, sep, pos):
		strng = strng.split(sep)
		return sep.join(strng[:pos]), sep.join(strng[pos:])


	def _up_check(self,url):
			parse_object = urlparse.urlparse(url)
			hostname = parse_object.netloc
			if parse_object.scheme == 'https':
				port = 443
				SSL = True
			else:
				port = 80
				SSL = False
			try:
				req_bytes = self._helpers.buildHttpRequest(URL(str(url)))
				res_bytes = self._callbacks.makeHttpRequest(hostname,port,SSL,req_bytes)
				res = self._helpers.analyzeResponse(res_bytes)
				if res.getStatusCode() not in WHITELIST_CODES:
					return url
			except Exception as e:
				print(e)
				print('SKIPPING : ',url)
				return None

	def process_queue(self,res):
		while not self.q.empty():
			url = self.q.get()
			furl = self._up_check(str(url))
			if furl is not None:
				#print(furl)
				self.temp_urls.append(furl)

	def _blf(self,baseRequestResponse,regex,host):
		res = self._helpers.bytesToString(baseRequestResponse.getResponse())
		re_r = regex.findall(res)
		if len(re_r) == 0:
			return
		re_r = list(set([tuple(j for j in re_r if j)[-1] for re_r in re_r]))
		re_r = list(set([i for i in re_r if i.startswith(tuple(WHITELIST_PATTERN))]))
		#re_r = [i.encode('utf-8').strip('') for i in re_r if isinstance(i,bytes)]
		#re_r = [i.replace('\\','/') for i in re_r]
		final = []
		for i in re_r:
			if i.startswith('//') and ' ' not in i:
				i = 'https:'+str(i)
				final.append(i)
			elif i.startswith('/') and ' ' not in i:
				if '.' in i.split('/')[1]:
					i = 'https:/'+str(i)
					final.append(i)
				else:
					i = str(host)+str(i)
					final.append(i)
			elif (i.startswith('http') or i.startswith('www.')) and ' ' not in i:
				final.append(i)
			elif i.startswith('../') and ' ' not in i:
				i = str(host)+'/'+str(i)
				final.append(i)
		for url in final:
			self.q.put(str(url))

		threads = []
		for i in range(int(BurpExtender.no_of_threads)):
			t = threading.Thread(target=self.process_queue,args=(baseRequestResponse,))
			threads.append(t)
			t.start()
		
		for j in threads:
			j.join()			
		return True


	def doPassiveScan(self,baseRequestResponse):
		reqInfo = self._helpers.analyzeRequest(baseRequestResponse.getHttpService(),baseRequestResponse.getRequest())
		if self._callbacks.isInScope(reqInfo.getUrl()) and str(self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getInferredMimeType()) in WHITELIST_MEMES:
			_HTTP = baseRequestResponse.getHttpService()
			print('ON : ',str(reqInfo.getUrl()))
			_host = str(_HTTP.getProtocol())+"://"+str(_HTTP.getHost())
			regex = re.compile(regex_str,re.VERBOSE)
			res = self._blf(baseRequestResponse,regex,_host)
			if res and len(self.temp_urls) > 0:
				final_urls = self.temp_urls[:]
				self.temp_urls[:] = []
				return [CustomScanIssue(baseRequestResponse.getHttpService(),self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
			[self._callbacks.applyMarkers(baseRequestResponse,None,None)],"Broken Link Hijacking",final_urls,"Low",_HTTP.getHost())]

	def consolidateDuplicateIssues(self,existingIssue,newIssue):
		return 1

	def extensionUnloaded(self):
		self._stdout.println("Extension was unloaded")
		return

class CustomScanIssue (IScanIssue):
	def __init__(self, httpService, url, httpMessages, name, detail, severity, hostbased):
		self._httpService = httpService
		self._url = url
		self._httpMessages = httpMessages
		self._name = name
		self._detail = detail
		self._severity = severity
		self._hostbased = hostbased


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
		host_b = []
		for i in self._detail:
			if self._hostbased not in i:
				host_b.append(str(i))
		if len(host_b) > 0:
			final = '<br>'.join(host_b)
			return str(final)
		else:
			final_without_host = '<br>'.join(self._detail)
			return str(final_without_host)

	def getRemediationDetail(self):
		pass

	def getHttpMessages(self):
		return self._httpMessages

	def getHttpService(self):
		return self._httpService
