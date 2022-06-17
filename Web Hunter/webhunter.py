#Date Writing 1401.2.5


import requests
import waf
from time import sleep
from colorama import Fore as color
import os,sys
import json

os.system("cls")
print(color.LIGHTRED_EX+"""
 __          __  _           _    _             _            
 \ \        / / | |         | |  | |           | |           
  \ \  /\  / /__| |__ ______| |__| |_   _ _ __ | |_ ___ _ __ 
   \ \/  \/ / _ \ '_ \______|  __  | | | | '_ \| __/ _ \ '__|
    \  /\  /  __/ |_) |     | |  | | |_| | | | | ||  __/ |   
     \/  \/ \___|_.__/      |_|  |_|\__,_|_| |_|\__\___|_|   
                                                             
                                                                 version 1.0""")
sleep(0.1)

print(color.RED+"""
------------------------------------------------------
|||           Developer: MahanXp                  |||
|||           Contact Telegram: @MaHaN_UniQuE     |||               
------------------------------------------------------             
""")
sleep(0.1)
print("--WelCome To My Tools--")
sleep(2)
print("")
print(color.RED+"[1] --Using CloudFlare")
sleep(0.1)
print("")
print(color.RED+"[2] --Http Methodes ")
sleep(0.1)
print("")
print(color.RED+"[3] --Inscure Http Header")
sleep(0.1)
print("")
print(color.RED+"[4] --Web Req Robots.txt ")
sleep(0.1)
print("")
print(color.RED+"[5] --To Finder Server WebSite")
sleep(0.1)
print("")
print(color.RED+"[6] --WAF")
sleep(0.1)
print("")
print(color.RED+"[7] --LOGOUT--")
sleep(0.1)
print("")

number= input(color.GREEN+"--Enter Number >>> ")
sleep(0.2)
print("")

if "1" in number:
        print(color.YELLOW+"In This Section We Can Find Out If The Site Uses The CloudFlare System Or Not")
        print("")
        website = input(color.GREEN+"Enter the Website = ")

        url = website

        hdr = {"User-Agent" :"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
            "Cookie":"_ga=GA1.2.1814430428.1538172038; pushNotification-shownCount-9429=1; PHPSESSID=c1fa43e53a5d6a2f9f34d8cc96cd46af; _gid=GA1.2.2144402071.1611854335; tlc=true",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding":"gzip, deflate, br"}

        payload = {"domain":url}

        req = requests.post("https://www.ultratools.com/tools/dnsLookupResult",payload,headers=hdr).text

        if "cloudflare" in req:

                print (color.GREEN+"\nWebSite Is Using CloudFlare !")

        else:

                print (color.RED+"WebSite Is Not Using CloudFlare")



elif "2" in number:
        print(color.YELLOW+"In This Section, We Check What Http Requests The WebSite Has")

        print("")
        
        web = input(color.GREEN+"Enter The WebSite Name "+"Using  " + color.RED+"Https:// >>  : ")
        verbs = ['GET', 'POST', 'PUT',"delete", 'OPTIONS', 'TRACE','TEST']

        hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)', 
                "Cookie" : "mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50" ,
                "Accept-Language" : "en-us,en" }

        for verb in verbs:
            try:
                req = requests.request(verb,web,headers=hdr)
                print (verb, req.status_code, req.reason)
                if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
                    print ('Possible Cross Site Tracing vulnerability(XST) Found')

            except:
                    pass



elif "3" in number:
    
        print(color.YELLOW+"Which Security Options Are There Or Not At Response Headers")
        print("")
        web = input(color.GREEN+"Enter The WebSite Name "+ "Using  " + color.RED+"Https:// >>  : ")


        url = web

        hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)', 
                "Cookie" : "mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50" ,
                "Accept-Language" : "en-us,en" }

        req = requests.get(url,headers=hdr)


        try:
            xssprotect = req.headers['X-XSS-Protection']
            if xssprotect != '1; mode=block':
                    print (color.CYAN+'X-XSS-Protection not set properly, XSS may be possible:', xssprotect)
        except:
            print (color.CYAN+'X-XSS-Protection not set, XSS may be possible')


        try:
            contenttype = req.headers['X-Content-Type-Options']
            if contenttype != 'nosniff':
                print (color.CYAN+'X-Content-Type-Options not set properly:',contenttype)
        except:
            print (color.CYAN+'X-Content-Type-Options not set')


        try:
            hsts = req.headers['Strict-Transport-Security']
        except:
            print (color.CYAN+'HSTS header not set, MITM attacks may be possible')

        try:
            csp = req.headers['Content-Security-Policy']
            print (color.CYAN+'Content-Security-Policy set:', csp)
        except:
            print (color.CYAN+'Content-Security-Policy missing')
            print (color.RED+'----')

    
elif "4" in number:

        
    mylist = ['robots.txt','search/','admin/',
    'login/','sitemap.xml','sitemap2.xml',
    'config.php','wp-login.php','log.txt','update.php',
    'INSTALL.pgsql.txt','user/login/','INSTALL.txt',
    'profiles/','scripts/',
    'LICENSE.txt','CHANGELOG.txt','themes/',
    'inculdes/''misc/','user/logout/',
    'user/register/','cron.php',
    'filter/tips/','comment/reply/',
    'xmlrpc.php','modules/','install.php',
    'MAINTAINERS.txt','user/password/','node/add/',
    'INSTALL.sqlite.txt','UPGRADE.txt','INSTALL.mysql.txt']

    print(color.YELLOW+"Extracts The robots.txt File")
    print('')
    url = input(color.GREEN+"Enter The WebSite Name "+"Using  " + color.RED+"Https:// >>  : ")

    for i in mylist:
        sleep(0.05)
        http = requests.get(url + "/" + i)
        if http.status_code == 200:
            print(color.GREEN + " [+] " + url+ " >> " +color.WHITE + i )
        else:
            print(color.RED + " [!] " + url + " >> " +color.WHITE + i)





elif "5" in number:
    print(color.YELLOW+"To Finder Server WebSite...")
    print('')
    ip = input(color.GREEN+"Enter The WebSite Name :")
    a = {"remoteAddress":ip}

    http = requests.post("https://domains.yougetsignal.com/domains.php",
    data = a).text

    data = json.loads(http)

    

    for i in data["domainArray"]:
        print(color.YELLOW + i[0])

elif "6" in number:
    print(color.YELLOW+"Waf")
    print("")
    req = input(color.GREEN+"Enter The WebSite Name "+"Using  " + color.RED+"Https:// >>  : ")

    r = requests.get(req)

    waf_ = waf.base_waf(r.headers,r.text)
    print(waf_.ll)

elif "7" in number:

    print(color.CYAN+"Thank You For Choosing The Tool! By By...")


else:
    print("Please True Number ")


    