from re import search,I 
import requests

def airlock(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\AAL[_-]?(SESS|LB)=',header[1],I) is not None
		if _ : break 
	if _:
		return "Airlock (Phion/Ergon)" 

def anquanbao(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'x-powered-by-anquanbao',header[1],I) is not None
		if _ : break
	if _: 
		return "Anquanbao Web Application Firewall (Anquanbao)" 

def armor(headers,content):
	_ = False
	_ |= search(r'This request has been blocked by website protection from Armor',content,I) is not None
	if _ : 
		return "Armor Protection (Armor Defense)" 

def asm(headers,content):
	_ = False
	_ |= search(r'The requested URL was rejected. Please consult with your administrator.',content,I) is not None
	if _ : 
		return "Application Security Manager (F5 Networks)" 

def aws(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\bAWS',header[1],I) is not None
	if _: 
		return "Amazon Web Services Web Application Firewall (Amazon)" 

def baidu(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'fh1|yunjiasu-nginx',header[1],I) is not None
		if _ : break
	if _ :
		return "Yunjiasu Web Application Firewall (Baidu)" 

def barracuda(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\Abarra_counter_session=|(\A|\b)barracuda_',header[1],I) is not None
		if _ : break
	if _:
		return "Barracuda Web Application Firewall (Barracuda Networks)"

def betterwpsecurity(headers,content):
	_ = False
	_ |= search(r'/wp-content/plugins/better-wp-security/',content,I) is not None
	if _:
		return "Better WP Security"

def bigip(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-cnection"
		_ |=  header[0].lower() == "x-wa-info"
		_ |= search(r'\ATS\w{4,}=|bigip|bigipserver|\AF5\Z',header[1],I) is not None
		if _: break
	if _ : 
		return "BIG-IP Application Security Manager (F5 Networks)"

def binarysec(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-binarysec-via"
		_ |=  header[0].lower() == "x-binarysec-nocache"
		_ |= search(r'binarySec',header[1],I) is not None
		if _: break
	if _ : 
		return "BinarySEC Web Application Firewall (BinarySEC)"

def blockdos(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'blockdos\.net',header[1],I) is not None
		if _: break
	if _ : 
		return "BlockDos"

def ciscoacexml(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'ace xml gateway',header[1],I) is not None
		if _: break
	if _ : 
		return "Cisco ACE XML Gateway (Cisco Systems)"

def cloudflare(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "cf-ray"
		_ |= search(r'__cfduid=|cloudflare-nginx|cloudflare[-]',header[1],I) is not None
		if _: break
	_ |= search(r"CloudFlare Ray ID:|var CloudFlare=",content) is not None
	if _ : 
		return "CloudFlare Web Application Firewall (CloudFlare)"

def cloudfront(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-amz-cf-id"
		_ |= search(r'cloudfront',header[1],I) is not None
		if _: break
	if _ : 
		return "CloudFront (Amazon)"

def comodo(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'protected by comodo waf',header[1],I) is not None
		if _: break
	if _ : 
		return "Comodo Web Application Firewall (Comodo)"

def datapower(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'x-backside-transport',header[1],I) is not None
		if _: break
	if _ : 
		return "IBM WebSphere DataPower (IBM)"

def denyall(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'sessioncookie=',header[1],I) is not None
		if _: break
	_ |= search(r"Condition Intercepted",content) is not None
	if _ :
		return "Deny All Web Application Firewall (DenyAll)"

def dotdefender(headers,content):
	_ = False
	for header in headers.items():
		_ |= header[0] == "x-dotdefender-denied"
		if _: break
	_ |= search(r"dotDefender Blocked Your Request",content) is not None
	if _ : 
		return "dotDefender (Applicure Technologies)"

def edgecast(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r"ecdf",header[1],I) is not None
		if _: break
	if _ : 
		return "EdgeCast WAF (Verizon)"

def expressionengine(headers,content):
	_ = False
	_ |= search(r"Invalid GET Data",content,I) is not None
	if _ : 
		return "ExpressionEngine (EllisLab)"

def fortiweb(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'fortiwafsid=',header[1],I) is not None
		if _: break
	if _ : 
		return "FortiWeb Web Application Firewall (Fortinet)"

def hyperguard(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'odsession=',header[1],I) is not None
		if _: break
	if _ :
		return "Hyperguard Web Application Firewall (art of defence)"

def incapsula(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'incap_ses|visid_incap',header[1],I) is not None
		_ |= search(r'incapsula',header[1],I) is not None
		if _:break
	_ |= search(r'Incapsula incident ID',content) is not None
	if _ : 
		return "Incapsula Web Application Firewall (Incapsula/Imperva)"

def isaserver(headers,content):
	_ = False
	_ |= search(r'The server denied the specified Uniform Resource Locator (URL). Contact the server administrator.',content) is not None
	_ |= search(r'The ISA Server denied the specified Uniform Resource Locator (URL)',content) is not None
	if _ : 
		return "ISA Server (Microsoft)"

def jiasule(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'__jsluid=|jsl_tracking',header[1],I) is not None
		_ |= search(r'jiasule-waf',header[1],I) is not None
		if _:break
	_ |= search(r'static\.jiasule\.com/static/js/http_error\.js',content) is not None
	if _ : 
		return "Jiasule Web Application Firewall (Jiasule)"

def knownsec(headers,content):
	_ = False
	_ |= search(r"url\('/ks-waf-error\.png'\)",content) is not None
	if _ : 
		return "KS-WAF (Knownsec)"

def kona(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'AkamaiGHost',header[1],I) is not None
		if _:break
	if _ : 
		return "KONA Security Solutions (Akamai Technologies)"

def modsecurity(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'Mod_Security|NOYB',header[1],I) is not None
		if _:break
	_ |= search(r'This error was generated by Mod_Security',content) is not None
	if _ : 
		return "ModSecurity: Open Source Web Application Firewall (Trustwave)"

def netcontinuum(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'NCI__SessionId=',header[1],I) is not None
		if _:break
	if _ : 
		return "NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)"

def netscaler(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'(ns_af=|citrix_ns_id|NSC_)',header[1],I) is not None
		_ |= search(r'ns.cache',header[1],I) is not None
		if _:break
	if _ : 
		return "NetScaler (Citrix Systems)"

def newdefend(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'newdefend',header[1],I) is not None
		if _:break
	if _ : 
		return "Newdefend Web Application Firewall (Newdefend)"

def nsfocus(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'nsfocus',header[1],I) is not None
		if _:break
	if _ : 
		return "NSFOCUS Web Application Firewall (NSFOCUS)"

def paloalto(headers,content):
	_ = False
	_ |= search(r'Access[^<]+has been blocked in accordance with company policy',content) is not None
	if _ : 
		return "Palo Alto Firewall (Palo Alto Networks)"

def profense(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'profense',header[1],I) is not None
		_ |= search(r'PLBSID=',header[1],I) is not None
		if _:break
	if _ : 
		return "Profense Web Application Firewall (Armorlogic)"

def radware(headers,content):
	_ = False
	for header in headers.items():
		_ |= header[0] == "x-sl-compstate"
		if _:break
	_ |= search(r'Unauthorized Activity Has Been Detected.+Case Number:',content) is not None
	if _ : 
		return "AppWall (Radware)"

def requestvalidationmode(headers,content):
	_ = False
	_ |= search(r'ASP.NET has detected data in the request that is potentially dangerous',content) is not None
	_ |= search(r'Request Validation has detected a potentially dangerous client input value',content) is not None	
	if _ : 
		return "ASP.NET RequestValidationMode (Microsoft)"

def safe3(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'Safe3 Web Firewall|Safe3',header[1],I) is not None
		_ |= search(r'Safe3WAF',header[1],I) is not None
		if _:break
	if _ : 
		return "Safe3 Web Application Firewall"

def safedog(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'safedog',header[1],I) is not None
		_ |= search(r'waf/2\.0',header[1],I) is not None
		if _:break
	if _ : 
		return "Safedog Web Application Firewall (Safedog)"

def secureiis(headers,content):
	_ = False
	_ |= search(r"SecureIIS[^<]+Web Server Protection",content) is not None
	_ |= search(r"http://www.eeye.com/SecureIIS/",content) is not None
	_ |= search(r"\?subject=[^>]*SecureIIS Error",content) is not None
	if _ : 
		return "SecureIIS Web Server Security (BeyondTrust)"

def senginx(headers,content):
	_ = False
	_ |= search(r"SENGINX-ROBOT-MITIGATION",content,I) is not None
	if _ : 
		return "SEnginx (Neusoft Corporation)"

def sitelock(headers,content):
	_ = False
	_ |= search(r"SiteLock Incident ID",content) is not None
	if _ : 
		return "TrueShield Web Application Firewall (SiteLock)"

def sonicwall(headers,content):
	_ = False
	_ |= search(r"This request is blocked by the SonicWALL",content) is not None
	_ |= search(r"Web Site Blocked.+\bnsa_banner",content) is not None
	_ |= headers['server'] == 'sonicwall'
	if _ : 
		return "SonicWALL (Dell)"

def sophos(headers,content):
	_ = False
	_ |= search(r"Powered by UTM Web Protection",content) is not None
	if _ : 
		return "UTM Web Protection (Sophos)"

def stingray(headers,content):
	_ = False
	_ |= search(r'X-Mapping-',str(headers.keys()),I) is not None
	if _ : 
		return "Stingray Application Firewall (Riverbed / Brocade)"

def sucuri(headers,content):
	_ = False
	_ |= search(r"Questions\?.+cloudproxy@sucuri\.net",content) is not None
	_ |= search(r"Sucuri WebSite Firewall - CloudProxy - Access Denied",content) is not None
	_ |= search('sucuri/cloudproxy',str(headers.values()),I) is not None
	if _ : 
		return "CloudProxy WebSite Firewall (Sucuri)"

def teros(headers,content):
	_ = False
	_ |= search(r'st8\(id|_wat|_wlf\)',str(headers.values()),I) is not None
	if _ : 
		return "Teros/Citrix Application Firewall Enterprise (Teros/Citrix Systems)"

def trafficshield(headers,content):
	_ = False
	_ |= headers['server'] == "F5-TrafficShield".lower()
	_ |= search(r'st8\(id|_wat|_wlf\)',str(headers.values()),I) is not None
	if _ : 
		return "TrafficShield (F5 Networks)"

def urlscan(headers,content):
	_ = False
	_ |= search('rejected-by-urlscan',str(headers.values()),I) is not None
	_ |= search(r'Rejected-By-UrlScan',content,I) is not None
	if _ : 
		return "UrlScan (Microsoft)"

def uspses(headers,content):
	_ = False
	_ |= headers['server'] == 'Secure Entry Server'.lower()
	if _ : 
		return "USP Secure Entry Server (United Security Providers)"

def varnish(headers,content):
	_ = False
	_ |= search(r'varnish|x-varnish',str(headers.values()),I) is not None
	if _ : 
		return "Varnish FireWall (OWASP)"

def airlock(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\AAL[_-]?(SESS|LB)=',header[1],I) is not None
		if _ : break 
	if _:
		return "Airlock (Phion/Ergon)" 

def anquanbao(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'x-powered-by-anquanbao',header[1],I) is not None
		if _ : break
	if _: 
		return "Anquanbao Web Application Firewall (Anquanbao)" 

def armor(headers,content):
	_ = False
	_ |= search(r'This request has been blocked by website protection from Armor',content,I) is not None
	if _ : 
		return "Armor Protection (Armor Defense)" 

def asm(headers,content):
	_ = False
	_ |= search(r'The requested URL was rejected. Please consult with your administrator.',content,I) is not None
	if _ : 
		return "Application Security Manager (F5 Networks)" 

def aws(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\bAWS',header[1],I) is not None
	if _: 
		return "Amazon Web Services Web Application Firewall (Amazon)" 

def baidu(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'fh1|yunjiasu-nginx',header[1],I) is not None
		if _ : break
	if _ :
		return "Yunjiasu Web Application Firewall (Baidu)" 

def barracuda(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'\Abarra_counter_session=|(\A|\b)barracuda_',header[1],I) is not None
		if _ : break
	if _:
		return "Barracuda Web Application Firewall (Barracuda Networks)"

def betterwpsecurity(headers,content):
	_ = False
	_ |= search(r'/wp-content/plugins/better-wp-security/',content,I) is not None
	if _:
		return "Better WP Security"

def bigip(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-cnection"
		_ |=  header[0].lower() == "x-wa-info"
		_ |= search(r'\ATS\w{4,}=|bigip|bigipserver|\AF5\Z',header[1],I) is not None
		if _: break
	if _ : 
		return "BIG-IP Application Security Manager (F5 Networks)"

def binarysec(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-binarysec-via"
		_ |=  header[0].lower() == "x-binarysec-nocache"
		_ |= search(r'binarySec',header[1],I) is not None
		if _: break
	if _ : 
		return "BinarySEC Web Application Firewall (BinarySEC)"

def blockdos(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'blockdos\.net',header[1],I) is not None
		if _: break
	if _ : 
		return "BlockDos"

def ciscoacexml(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'ace xml gateway',header[1],I) is not None
		if _: break
	if _ : 
		return "Cisco ACE XML Gateway (Cisco Systems)"

def cloudflare(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "cf-ray"
		_ |= search(r'__cfduid=|cloudflare-nginx|cloudflare[-]',header[1],I) is not None
		if _: break
	_ |= search(r"CloudFlare Ray ID:|var CloudFlare=",content) is not None
	if _ : 
		return "CloudFlare Web Application Firewall (CloudFlare)"

def cloudfront(headers,content):
	_ = False
	for header in headers.items():
		_ |=  header[0].lower() == "x-amz-cf-id"
		_ |= search(r'cloudfront',header[1],I) is not None
		if _: break
	if _ : 
		return "CloudFront (Amazon)"

def comodo(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'protected by comodo waf',header[1],I) is not None
		if _: break
	if _ : 
		return "Comodo Web Application Firewall (Comodo)"

def datapower(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'x-backside-transport',header[1],I) is not None
		if _: break
	if _ : 
		return "IBM WebSphere DataPower (IBM)"

def denyall(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'sessioncookie=',header[1],I) is not None
		if _: break
	_ |= search(r"Condition Intercepted",content) is not None
	if _ :
		return "Deny All Web Application Firewall (DenyAll)"

def dotdefender(headers,content):
	_ = False
	for header in headers.items():
		_ |= header[0] == "x-dotdefender-denied"
		if _: break
	_ |= search(r"dotDefender Blocked Your Request",content) is not None
	if _ : 
		return "dotDefender (Applicure Technologies)"

def edgecast(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r"ecdf",header[1],I) is not None
		if _: break
	if _ : 
		return "EdgeCast WAF (Verizon)"

def expressionengine(headers,content):
	_ = False
	_ |= search(r"Invalid GET Data",content,I) is not None
	if _ : 
		return "ExpressionEngine (EllisLab)"

def fortiweb(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'fortiwafsid=',header[1],I) is not None
		if _: break
	if _ : 
		return "FortiWeb Web Application Firewall (Fortinet)"


def hyperguard(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'odsession=',header[1],I) is not None
		if _: break
	if _ :
		return "Hyperguard Web Application Firewall (art of defence)"

def incapsula(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'incap_ses|visid_incap',header[1],I) is not None
		_ |= search(r'incapsula',header[1],I) is not None
		if _:break
	_ |= search(r'Incapsula incident ID',content) is not None
	if _ : 
		return "Incapsula Web Application Firewall (Incapsula/Imperva)"

def isaserver(headers,content):
	_ = False
	_ |= search(r'The server denied the specified Uniform Resource Locator (URL). Contact the server administrator.',content) is not None
	_ |= search(r'The ISA Server denied the specified Uniform Resource Locator (URL)',content) is not None
	if _ : 
		return "ISA Server (Microsoft)"

def jiasule(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'__jsluid=|jsl_tracking',header[1],I) is not None
		_ |= search(r'jiasule-waf',header[1],I) is not None
		if _:break
	_ |= search(r'static\.jiasule\.com/static/js/http_error\.js',content) is not None
	if _ : 
		return "Jiasule Web Application Firewall (Jiasule)"

def knownsec(headers,content):
	_ = False
	_ |= search(r"url\('/ks-waf-error\.png'\)",content) is not None
	if _ : 
		return "KS-WAF (Knownsec)"

def kona(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'AkamaiGHost',header[1],I) is not None
		if _:break
	if _ : 
		return "KONA Security Solutions (Akamai Technologies)"

def modsecurity(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'Mod_Security|NOYB',header[1],I) is not None
		if _:break
	_ |= search(r'This error was generated by Mod_Security',content) is not None
	if _ : 
		return "ModSecurity: Open Source Web Application Firewall (Trustwave)"

def netcontinuum(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'NCI__SessionId=',header[1],I) is not None
		if _:break
	if _ : 
		return "NetContinuum Web Application Firewall (NetContinuum/Barracuda Networks)"

def netscaler(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'(ns_af=|citrix_ns_id|NSC_)',header[1],I) is not None
		_ |= search(r'ns.cache',header[1],I) is not None
		if _:break
	if _ : 
		return "NetScaler (Citrix Systems)"

def newdefend(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'newdefend',header[1],I) is not None
		if _:break
	if _ : 
		return "Newdefend Web Application Firewall (Newdefend)"

def nsfocus(headers,content):
	_ = False
	for header in headers.items():
		_ |= search(r'nsfocus',header[1],I) is not None
		if _:break
	if _ : 
		return "NSFOCUS Web Application Firewall (NSFOCUS)"

def wallarm(headers,content):
	_ = False
	_ |= headers['server'] == 'nginx-wallarm'
	if _ : 
		return "Wallarm Web Application Firewall (Wallarm)" 

def webknight(headers,content):
	_ = False
	_ |= headers['server'] == 'WebKnight'.lower()
	if _ : 
		return "WebKnight Application Firewall (AQTRONIX)"

def yundun(headers,content):
	_ = False
	_ |= headers['server'] == 'YUNDUN'
	if 'x-cache' in headers.keys():
		_ |= headers['x-cache'] == 'YUNDUN'
	if _ : 
		return "Yundun Web Application Firewall (Yundun)"

def yunsuo(headers,content):
	_ = False
	_ |= search('<img class=\"yunsuologo\"',content) is not None
	if 'cookie' in headers.keys():
		_ |= search('yunsuo_session',headers['cookie'],I) is not None
	if _ : 
		return "Yunsuo Web Application Firewall (Yunsuo)"

def genuis_x(headers,content):
	_ = False
	_ |= search('GENIUS-X',headers['server']) is not None
	if _ : 
		return "Anti-DDoS & Website Security by GENIU"

'''
l = []

for i in dir():

		if "__" in i or len(i) == 1:
			continue
		else:
				l.append(i)

for i in l:

	print("if "+i+"(headers,text) != None:ll.append("+i+"(headers,text))" )

#r = requests.get("https://ultrasec.org")
'''

class base_waf():

	def __init__(self,headers,text):

			ll = []

			if airlock(headers,text) != None:ll.append(airlock(headers,text))
			if anquanbao(headers,text) != None:ll.append(anquanbao(headers,text))
			if armor(headers,text) != None:ll.append(armor(headers,text))
			if asm(headers,text) != None:ll.append(asm(headers,text))
			if aws(headers,text) != None:ll.append(aws(headers,text))
			if baidu(headers,text) != None:ll.append(baidu(headers,text))
			if barracuda(headers,text) != None:ll.append(barracuda(headers,text))
			if betterwpsecurity(headers,text) != None:ll.append(betterwpsecurity(headers,text))
			if bigip(headers,text) != None:ll.append(bigip(headers,text))
			if binarysec(headers,text) != None:ll.append(binarysec(headers,text))
			if blockdos(headers,text) != None:ll.append(blockdos(headers,text))
			if ciscoacexml(headers,text) != None:ll.append(ciscoacexml(headers,text))
			if cloudflare(headers,text) != None:ll.append(cloudflare(headers,text))
			if cloudfront(headers,text) != None:ll.append(cloudfront(headers,text))
			if comodo(headers,text) != None:ll.append(comodo(headers,text))
			if datapower(headers,text) != None:ll.append(datapower(headers,text))
			if denyall(headers,text) != None:ll.append(denyall(headers,text))
			if dotdefender(headers,text) != None:ll.append(dotdefender(headers,text))
			if edgecast(headers,text) != None:ll.append(edgecast(headers,text))
			if expressionengine(headers,text) != None:ll.append(expressionengine(headers,text))
			if fortiweb(headers,text) != None:ll.append(fortiweb(headers,text))
			if genuis_x(headers,text) != None:ll.append(genuis_x(headers,text))
			if hyperguard(headers,text) != None:ll.append(hyperguard(headers,text))
			if incapsula(headers,text) != None:ll.append(incapsula(headers,text))
			if isaserver(headers,text) != None:ll.append(isaserver(headers,text))
			if jiasule(headers,text) != None:ll.append(jiasule(headers,text))
			if knownsec(headers,text) != None:ll.append(knownsec(headers,text))
			if kona(headers,text) != None:ll.append(kona(headers,text))
			if modsecurity(headers,text) != None:ll.append(modsecurity(headers,text))
			if netcontinuum(headers,text) != None:ll.append(netcontinuum(headers,text))
			if netscaler(headers,text) != None:ll.append(netscaler(headers,text))
			if newdefend(headers,text) != None:ll.append(newdefend(headers,text))
			if nsfocus(headers,text) != None:ll.append(nsfocus(headers,text))
			if paloalto(headers,text) != None:ll.append(paloalto(headers,text))
			if profense(headers,text) != None:ll.append(profense(headers,text))
			if radware(headers,text) != None:ll.append(radware(headers,text))
			if requestvalidationmode(headers,text) != None:ll.append(requestvalidationmode(headers,text))
			if safe3(headers,text) != None:ll.append(safe3(headers,text))
			if safedog(headers,text) != None:ll.append(safedog(headers,text))
			if secureiis(headers,text) != None:ll.append(secureiis(headers,text))
			if senginx(headers,text) != None:ll.append(senginx(headers,text))
			if sitelock(headers,text) != None:ll.append(sitelock(headers,text))
			if sonicwall(headers,text) != None:ll.append(sonicwall(headers,text))
			if sophos(headers,text) != None:ll.append(sophos(headers,text))
			if stingray(headers,text) != None:ll.append(stingray(headers,text))
			if sucuri(headers,text) != None:ll.append(sucuri(headers,text))
			if teros(headers,text) != None:ll.append(teros(headers,text))
			if trafficshield(headers,text) != None:ll.append(trafficshield(headers,text))
			if urlscan(headers,text) != None:ll.append(urlscan(headers,text))
			if uspses(headers,text) != None:ll.append(uspses(headers,text))
			if varnish(headers,text) != None:ll.append(varnish(headers,text))
			if wallarm(headers,text) != None:ll.append(wallarm(headers,text))
			if webknight(headers,text) != None:ll.append(webknight(headers,text))
			if yundun(headers,text) != None:ll.append(yundun(headers,text))
			if yunsuo(headers,text) != None:ll.append(yunsuo(headers,text))

			self.ll = ll





