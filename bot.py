from telegram.ext import *
import random
'''
We need these libraries for Web-Killers:
import socket
import requests
import builtwith
import ipapi
import json
'''

api_key="1982384940:AAFlNGZk7kK7cEo61paPnFCcTH5_JHh-lCk"

known_user = False

log_position = 0
sign_position = 0

change_username = False
change_password = False

contact_info = {}
known_persons = [{'username':'shayan86', 'password':'webkiller86', 'history':['https://icons8.com/','https://github.com/shayanrazavi/Data-Analysis-Project']}]
pass_persons = [{'username':'shayan86', 'password':'webkiller86', 'history':['https://icons8.com/','https://github.com/shayanrazavi/Data-Analysis-Project']}]

cryptography_bool = False
decryption_bool = False

cloudflare_bool = False
cms_bool = False
dns_lookup_bool = False
find_admin_bool = False
find_shared_dns_bool = False
http_header_bool = False
ip_location_bool = False
port_scanner_bool = False
reverse_ip_bool = False
traceroute_bool = False
whois_bool = False

def cloudflare(url):
    '''
    subdom = ['ftp', 'cpanel', 'webmail', 'localhost', 'local', 'mysql', 'forum', 'driect-connect', 'blog', 'vb', 'forums', 'home', 'direct', 'forums', 'mail', 'access', 'admin', 'administrator', 'email', 'downloads', 'ssh', 'owa', 'bbs', 'webmin', 'paralel', 'parallels', 'www0', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'shop', 'api', 'blogs', 'test', 'mx1', 'cdn', 'mysql', 'mail1', 'secure', 'server', 'ns1', 'ns2', 'smtp', 'vpn', 'm', 'mail2', 'postal', 'support', 'web', 'dev']

    site = url
    reout = ''
    for sub in subdom:
        try:
            host= str(sub) + "." + str(site)
            bypass= socket.gethostbyname(str(host))
            reout += (" [!] CloudFlare Bypass " + str(bypass) + ' | ' + str(host) + '\n')
        except:
            reout += ("don't have" + '\n')
            
    return reout'''
    return "Under Construction..."

def cms(url):
    '''
    site = url
    if not 'https://' in site and not 'http://' in site:
        site = "http://" + site
    info = builtwith.parse(site)
    reout = ''
    for name in info:
        value=""
        for val in info[str(name)]:
            name = name.replace("-",' ')
            name = name.title()
            value = value+str(val)+' '
        reout += ("\n"+name+":"+value + '\n')
    return reout'''
    return "Under Construction..."

def dns_lookup(url):
    '''
    site = url
    result = requests.get("http://api.hackertarget.com/dnslookup/?q="+ site).text
    return (result)
    '''
    return "Under Construction..."

def find_admin(url):
    '''
    list_=['admin/','administrator/','login.php','administration/','admin1/','admin2/','admin3/','admin4/','admin5/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
'memberadmin/','administratorlogin/','adm/','account.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp','/login.aspx',
'admin_area/admin.asp','admin_area/login.asp','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/admin.html','admin_area/login.html','admin_area/index.html','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','admin/controlpanel.html','admin.html','admin/cp.html','cp.html',
'administrator/index.html','administrator/login.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html','moderator.html',
'moderator/login.html','moderator/admin.html','account.html','controlpanel.html','admincontrol.html','admin_login.html','panel-administracion/login.html',
'admin/home.asp','admin/controlpanel.asp','admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','admin/cp.asp','cp.asp',
'administrator/account.asp','administrator.asp','acceso.asp','login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','administrator/login.asp',
'moderator/admin.asp','controlpanel.asp','admin/account.html','adminpanel.html','webadmin.html','administration','pages/admin/admin-login.html','admin/admin-login.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','user.asp','user.html','admincp/index.asp','admincp/login.asp','admincp/index.html',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html','adminarea/login.html',
'panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admin/admin_login.html',
'admincontrol/login.html','adm/index.html','adm.html','admincontrol.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp',
'webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','adminLogin.asp',
'admin/adminLogin.asp','home.asp','admin.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','admin-login.html',
'panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','administrator/index.asp',
'admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp',
'adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.asp','siteadmin/login.html','memberadmin/','administratorlogin/','adm/','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php',
'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.php','admin.php','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php',
'administrator/account.php','administrator.php','admin_area/admin.html','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php',
'bb-admin/index.html','bb-admin/login.html','acceso.php','bb-admin/admin.html','admin/home.html','login.php','modelsearch/login.php','moderator.php','moderator/login.php',
'moderator/admin.php','account.php','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.php','admincontrol.php',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.php','adminarea/index.html','adminarea/admin.html',
'webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.php','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.php','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php','home.php','admin.php','adminarea/index.php',
'adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php',
'modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','usuarios/login.php',
'adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','adm/','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin/account.cfm',
'admin_area/admin.cfm','admin_area/login.cfm','siteadmin/login.cfm','siteadmin/index.cfm','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cfm','admin.cfm','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cfm','cp.cfm','administrator/index.cfm','administrator/login.cfm','nsw/admin/login.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm',
'administrator/account.cfm','administrator.cfm','admin_area/admin.html','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm',
'moderator/admin.cfm','account.cfm','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cfm','admincontrol.cfm',
'admin/adminLogin.html','acceso.cfm','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cfm','adminarea/index.html','adminarea/admin.html',
'webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cfm','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cfm','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cfm','wp-login.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','admin.cfm','adminarea/index.cfm',
'adminarea/admin.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm',
'modelsearch/admin.cfm','admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm','admin2/login.cfm','admin2/index.cfm','usuarios/login.cfm',
'adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm','memberadmin.cfm','administratorlogin.cfm','adminLogin/','admin_area/','panel-administracion/','instadmin/','login.aspx',
'memberadmin/','administratorlogin/','adm/','admin/account.aspx','admin/index.aspx','admin/login.aspx','admin/admin.aspx','admin/account.aspx',
'admin_area/admin.aspx','admin_area/login.aspx','siteadmin/login.aspx','siteadmin/index.aspx','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.aspx','bb-admin/index.aspx','bb-admin/login.aspx','bb-admin/admin.aspx','admin/home.aspx','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.aspx','admin.aspx','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.aspx','cp.aspx','administrator/index.aspx','administrator/login.aspx','nsw/admin/login.aspx','webadmin/login.aspx','admin/admin_login.aspx','admin_login.aspx',
'administrator/account.aspx','administrator.aspx','admin_area/admin.html','pages/admin/admin-login.aspx','admin/admin-login.aspx','admin-login.aspx',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.aspx','modelsearch/login.aspx','moderator.aspx','moderator/login.aspx',
'moderator/admin.aspx','acceso.aspx','account.aspx','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.aspx','admincontrol.aspx',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.aspx','adminarea/index.html','adminarea/admin.html',
'webadmin.aspx','webadmin/index.aspx','webadmin/admin.aspx','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.aspx','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.aspx','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.aspx','wp-login.aspx','adminLogin.aspx','admin/adminLogin.aspx','home.aspx','admin.aspx','adminarea/index.aspx',
'adminarea/admin.aspx','adminarea/login.aspx','panel-administracion/index.aspx','panel-administracion/admin.aspx','modelsearch/index.aspx',
'modelsearch/admin.aspx','admincontrol/login.aspx','adm/admloginuser.aspx','admloginuser.aspx','admin2.aspx','admin2/login.aspx','admin2/index.aspx','usuarios/login.aspx',
'adm/index.aspx','adm.aspx','affiliate.aspx','adm_auth.aspx','memberadmin.aspx','administratorlogin.aspx','memberadmin/','administratorlogin/','adm/','admin/account.js','admin/index.js','admin/login.js','admin/admin.js','admin/account.js',
'admin_area/admin.js','admin_area/login.js','siteadmin/login.js','siteadmin/index.js','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.js','bb-admin/index.js','bb-admin/login.js','bb-admin/admin.js','admin/home.js','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.js','admin.js','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.js','cp.js','administrator/index.js','administrator/login.js','nsw/admin/login.js','webadmin/login.js','admin/admin_login.js','admin_login.js',
'administrator/account.js','administrator.js','admin_area/admin.html','pages/admin/admin-login.js','admin/admin-login.js','admin-login.js',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.js','modelsearch/login.js','moderator.js','moderator/login.js',
'moderator/admin.js','account.js','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.js','admincontrol.js',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.js','adminarea/index.html','adminarea/admin.html',
'webadmin.js','webadmin/index.js','acceso.js','webadmin/admin.js','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.js','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.js','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.js','wp-login.js','adminLogin.js','admin/adminLogin.js','home.js','admin.js','adminarea/index.js',
'adminarea/admin.js','adminarea/login.js','panel-administracion/index.js','panel-administracion/admin.js','modelsearch/index.js',
'modelsearch/admin.js','admincontrol/login.js','adm/admloginuser.js','admloginuser.js','admin2.js','admin2/login.js','admin2/index.js','usuarios/login.js',
'adm/index.js','adm.js','affiliate.js','adm_auth.js','memberadmin.js','administratorlogin.js','bb-admin/index.cgi','bb-admin/login.cgi','bb-admin/admin.cgi','admin/home.cgi','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.cgi','admin.cgi','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.cgi','cp.cgi','administrator/index.cgi','administrator/login.cgi','nsw/admin/login.cgi','webadmin/login.cgi','admin/admin_login.cgi','admin_login.cgi',
'administrator/account.cgi','administrator.cgi','admin_area/admin.html','pages/admin/admin-login.cgi','admin/admin-login.cgi','admin-login.cgi',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.cgi','modelsearch/login.cgi','moderator.cgi','moderator/login.cgi',
'moderator/admin.cgi','account.cgi','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.cgi','admincontrol.cgi',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.cgi','adminarea/index.html','adminarea/admin.html',
'webadmin.cgi','webadmin/index.cgi','acceso.cgi','webadmin/admin.cgi','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.cgi','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.cgi','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.cgi','wp-login.cgi','adminLogin.cgi','admin/adminLogin.cgi','home.cgi','admin.cgi','adminarea/index.cgi',
'adminarea/admin.cgi','adminarea/login.cgi','panel-administracion/index.cgi','panel-administracion/admin.cgi','modelsearch/index.cgi',
'modelsearch/admin.cgi','admincontrol/login.cgi','adm/admloginuser.cgi','admloginuser.cgi','admin2.cgi','admin2/login.cgi','admin2/index.cgi','usuarios/login.cgi',
'adm/index.cgi','adm.cgi','affiliate.cgi','adm_auth.cgi','memberadmin.cgi','administratorlogin.cgi','admin_area/admin.brf','admin_area/login.brf','siteadmin/login.brf','siteadmin/index.brf','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
'admin_area/index.brf','bb-admin/index.brf','bb-admin/login.brf','bb-admin/admin.brf','admin/home.brf','admin_area/login.html','admin_area/index.html',
'admin/controlpanel.brf','admin.brf','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
'admin/cp.brf','cp.brf','administrator/index.brf','administrator/login.brf','nsw/admin/login.brf','webadmin/login.brfbrf','admin/admin_login.brf','admin_login.brf',
'administrator/account.brf','administrator.brf','acceso.brf','admin_area/admin.html','pages/admin/admin-login.brf','admin/admin-login.brf','admin-login.brf',
'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','login.brf','modelsearch/login.brf','moderator.brf','moderator/login.brf',
'moderator/admin.brf','account.brf','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.brf','admincontrol.brf',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.brf','adminarea/index.html','adminarea/admin.html',
'webadmin.brf','webadmin/index.brf','webadmin/admin.brf','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.brf','moderator.html',
'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.brf','account.html','controlpanel.html','admincontrol.html',
'panel-administracion/login.brf','wp-login.brf','adminLogin.brf','admin/adminLogin.brf','home.brf','admin.brf','adminarea/index.brf',
'adminarea/admin.brf','adminarea/login.brf','panel-administracion/index.brf','panel-administracion/admin.brf','modelsearch/index.brf',
'modelsearch/admin.brf','admincontrol/login.brf','adm/admloginuser.brf','admloginuser.brf','admin2.brf','admin2/login.brf','admin2/index.brf','usuarios/login.brf',
'adm/index.brf','adm.brf','affiliate.brf','adm_auth.brf','memberadmin.brf','administratorlogin.brf','cpanel','cpanel.php','cpanel.html',]

    if "http" in url:
        url = (url+"/")

    elif "https" in url:
        url = (url+"/")
        
    else:
        url = ('http://'+url+"/")

    reout = ''
    for i in list_:
        r = requests.get(url+i)
        if r.status_code == 200:
            reout += ("[+] "+url+i+" Found" + '\n')
        else:
            reout += ("[-] "+url+i+" Not Found" + '\n')
    '''
    return "Under Construction..."

def find_shared_dns(url):
    '''
    site = url
    result = requests.get("https://api.hackertarget.com/findshareddns/?q="+ site).text
    print(result)
    '''
    return "Under Construction..."

def http_header(url):
    '''
    site = url
    result = requests.get("https://api.hackertarget.com/httpheaders/?q="+ site).text
    return (result)
    '''
    return "Under Construction..."

def ip_location(url):
    '''
    site = url
    a = site.count(".")
    if a<3 and a>0:
       bypass= socket.gethostbyname(str(site))
       site = bypass
    source = ipapi.location(ip=site,key=None)
    
    result = ''
    result += (" [!]"+" See your info" + '\n')
    result += (" [!]"+" ip = "+ source["ip"] + '\n'))
    result += (" [!]"+" city = " + source["city"] + '\n'))
    result += (" [!]"+" region = "+ source["region"] + '\n'))
    result += (" [!]"+" id country = "+source["country"] + '\n'))
    result += (" [!]"+" country = "+ source["country_name"] + '\n'))
    result += (" [!]"+" Calling Code = "+source["country_calling_code"] + '\n'))
    result += (" [!]"+" Languages = "+source["languages"])
    result += (" [!]"+" org = "+ source["org"] + '\n'))
    
    return result
    '''
    return "Under Construction..."

def port_scanner(url):
    '''
    site = url
    result = requests.get("http://api.hackertarget.com/nmap/?q="+ site).text
    return (result)
    '''
    return "Under Construction..."

def reverse_ip(url):
    '''
    site = input("please enter the adress of site (it's not a reqeast) :")
    data = {"remoteAddress":site}
    link = requests.post("https://domains.yougetsignal.com/domains.php", data)
    source = json.loads(link.content)
    
    result = (source + '\n')
    for data in source["domainArray"]:
        result += (""+data[0]+"\n"+'\n')
    return result
    '''
    return "Under Construction..."

def traceroute(url):
    '''
    site = url
    a=site.count(".")
    if a<3 and a>0:
       bypass = socket.gethostbyname(str(site))
       site = bypass
    result = requests.get("http://api.hackertarget.com/mtr/?q="+ site).text
    
    return (result)
    '''
    return "Under Construction..."

def whois(url):
    '''
    site = url
    result = requests.get("http://api.hackertarget.com/whois/?q="+ site).text
    return (result)
    '''
    return "Under Construction..."





def start_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    sign_position = 0
    change_username = False
    change_password = False
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    start_message = '''I can help you to get secret information about different website.

You can control me by sending these commands:

Account setting:
/sign_up - create a new account
/sign_out - delete account
/log_in - entry in account
/log_out - exit from account
/edit_username - change the username
/edit_password - change the password

Website information:
/cloudflare - check cloudflare
/cms - take cms
/dns_lookup - lookup dns
/find_admin - find the website admin address
/find_shared_dns - find the shared dns
/http_header - take http header of websites
/ip_location - find ip location 
/port_scanner - sacn the ports
/reverse_ip - reverse ip :))
/traceroute - trace the route
/whois - take information of websites

Search on history:
/clear_history - clear the URLs history
/overview_history - view URLs history

/cancel - cancel the previous command'''
    update.message.reply_text(start_message)

def help_command(update,context):
    help_message = '''You can use the following tags to solve your problem:))

You can control me by sending these commands:

Account setting:
/sign_up - create a new account
/sign_out - delete account
/log_in - entry in account
/log_out - exit from account
/edit_username - change the username
/edit_password - change the password

Website information:
/cloudflare - check cloudflare
/cms - take cms
/dns_lookup - lookup dns
/find_admin - find the website admin address
/find_shared_dns - find the shared dns
/http_header - take http header of websites
/ip_location - find ip location 
/port_scanner - sacn the ports
/reverse_ip - reverse ip :))
/traceroute - trace the route
/whois - take information of websites

Search on history:
/clear_history - clear the URLs history
/overview_history - view URLs history

/cancel - cancel the previous command'''
    update.message.reply_text(help_message)
        
def help2_command(update,context):
    global known_user
    if known_user == True:
        secret_help_message = '''Welcome to Encryption system

You can control me by sending these commands:

Secret tags:
/encode - encrypt a text
/decode - break a password

/help /help2'''
        update.message.reply_text(secret_help_message)
        
    else:
        update.message.reply_text("I dont understand you! Please try again. /help")
        
def sign_up_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    sign_position = 1
    log_position = 0
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    contact_info = {}
    
    update.message.reply_text("Alright, How are we going to call you? Please choose a user name for your account.")
    
def sign_out_command(update,context):
    global sign_position, log_position, contact_info, known_persons, cryptography_bool, decryption_bool, known_user
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    if log_position == 3:
        log_position = 0
        sign_position = 0
        for i in known_persons:
            if i == contact_info:
                known_persons.remove(i)
        contact_info = {}
        known_user = False
        update.message.reply_text("Success! Your account has been deleted. /help")
    else:
        if log_position != 3:
            log_position = 0
        update.message.reply_text("Error, you must log in to your account before you can sign out. /log_in /sign_up")
    
def log_in_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    log_position = 1
    sign_position = 0
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    contact_info = {}
    
    update.message.reply_text("Please enter your username:")
    
def log_out_command(update,context):
    global sign_position, log_position, contact_info, known_user, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    if log_position == 3:
        contact_info = {}
        log_position = 0
        sign_position = 0
        known_user = False
        update.message.reply_text("Success! You are logged out. /help")
    else:
        if log_position != 3:
            log_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can log out. /log_in /sign_up")

        

def edit_username_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    cryptography_bool = False
    decryption_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_password = False
    
    if log_position == 3:
        change_username = True
        update.message.reply_text("Ok, please enter a new user name:")
    else:
        change_username = False
        update.message.reply_text("Error, you must log in or sign in to your account before you can change user name. /log_in /sign_up")


def edit_password_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    cryptography_bool = False
    decryption_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    
    if log_position == 3:
        change_password = True
        update.message.reply_text("Ok, please enter a new password:")
    else:
        change_password = False
        update.message.reply_text("Error, you must log in or sign in to your account before you can change password. /log_in /sign_up")
        

def cancel_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False

        
        
def cloudflare_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = True
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def cms_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = True
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def dns_lookup_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = True
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def find_admin_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = True
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def find_shared_dns_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = True
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def http_header_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = True
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def ip_location_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = True
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def port_scanner_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = True
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def reverse_ip_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = True
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def traceroute_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = True
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")

def whois_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = True
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    update.message.reply_text("please enter the adress of site:")
    
    
    
    
    
def cryptography_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool, known_user
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    
    if known_user == True:
        cryptography_bool = True
        update.message.reply_text('Please enter your message:')
def decryption_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool, known_user
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    if known_user == True:
        decryption_bool = True
        update.message.reply_text('Please enter your password:')
        
        
def clear_history_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool, known_persons
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    if log_position == 3:
        '''
        for i in known_persons:
            if i['username'] == contact_info['username'] and i['password'] == contact_info['password']:
                known_persons[i]['history'] = []
        '''
        contact_info['history'] = []
        
        update.message.reply_text("Success! history has been cleared. /help")
    
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can clear history. /log_in /log_out")

    
def overview_history_command(update,context):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool, known_user
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    
    if log_position == 3:
        history = contact_info['history']
        overview = ''
        for i in history:
            overview += (i + '\n')
            
        if len(overview) == 0:
            update.message.reply_text("history is empty!")
        else:
            update.message.reply_text(overview)
    
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can view history. /log_in /log_out")


        
def output_response(text_input):
    global sign_position, log_position, contact_info, cryptography_bool, decryption_bool, known_user, known_persons
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    user_message = str(text_input)
    
    if sign_position == 1:
        contact_info['username'] = user_message
        sign_position = 2
        return ("Good. Now let's choose a password for your account.It must contain letters and numbers and symbols. Like this, for example: SinShinbot1400")
    
    if sign_position == 2:
        contact_info['password'] = user_message
        contact_info['history'] = []
        sign_position = 3
        log_position = 3
        known_persons.append(contact_info)
        return ("Success! Your account is build. /help")
        
    if log_position == 1:
        check = False
        for i in known_persons:
            if i['username'] == user_message:
                check = True
        
        if check == True:
            contact_info['username'] = user_message
            log_position = 2
            return ("well, Please enter your password:")
        else:
            contact_info = {}
            log_position = 1
            return ("Wrong! Please try again:")
        
    if log_position == 2:
        check = False
        save_history = []
        for i in known_persons:
            if i['username'] == contact_info['username'] and i['password'] == user_message:

                check = True
                save_history.extend(i['history'])
                for j in pass_persons:
                    if i['username'] == j['username'] and i['password'] == j['password']:
                        known_user = True
                
        if check == True:
            contact_info['password'] = user_message
            contact_info['history'] = save_history
            log_position = 3
            if known_user == True:
                secret_help_message = '''Welcome to Encryption system

You can control me by sending these commands:

Secret tags:
/encode - encrypt a text
/decode - break a password

/help /help2'''
                return (f"Success! Hello dear {contact_info['username']}, Welcome to SinShin" + '\n' + secret_help_message)

            return (f"Success! Hello dear {contact_info['username']}, Welcome to SinShin /help")
        else:
            log_position = 2
            return ("Wrong! Please try again:")
            
    if change_username == True:
        for i in known_persons:
            if i['username'] == contact_info['username'] and i['password'] ==  contact_info['password']:
                known_persons.remove(i)
                
        contact_info['username'] = user_message
        change_username = False
        known_persons.append(contact_info)
        return ("Success! Your username has been changed. /help")
         
    if change_password == True:
        for i in known_persons:
            if i['username'] == contact_info['username'] and i['password'] ==  contact_info['password']:
                known_persons.remove(i)
        
        contact_info['password'] = user_message
        known_persons.append(contact_info)
        change_password = False
        return ("Success! Your password has been changed. /help")
        
    if cloudflare_bool == True:
        output = cloudflare(user_message)
        cloudflare_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if cms_bool == True:
        output = cms(user_message)
        cms_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if dns_lookup_bool == True:
        output = dns_lookup(user_message)
        dns_lookup_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if find_admin_bool == True:
        output = find_admin(user_message)
        find_admin_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if find_shared_dns_bool == True:
        output = find_shared_dns(user_message)
        find_shared_dns_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if http_header_bool == True:
        output = http_header(user_message)
        http_header_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if ip_location_bool == True:
        output = ip_location(user_message)
        ip_location_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if port_scanner_bool == True:
        output = port_scanner(user_message)
        port_scanner_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if reverse_ip_bool == True:
        output = reverse_ip(user_message)
        reverse_ip_bool = False
        '''for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if traceroute_bool == True:
        output = traceroute(user_message)
        traceroute_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
    
    if whois_bool == True:
        output = whois(user_message)
        whois_bool = False
        '''
        for i in known_persons:
            if i == contact_info:
                known_persons[i]['history'].append(user_message)'''
                
        contact_info['history'].append(user_message)
        return (output)
        
    if cryptography_bool == True:
        def asembly(str_input):
            lst_output = []
            for i in str_input:
                Ascii = str(ord(i))
                if len(Ascii) == 1:
                    Ascii = '00'+Ascii
                if len(Ascii) == 2:
                    Ascii = '0'+Ascii
        
                k2 = random.randint(1,6)
                if k2 == 1:
                    Ascii = Ascii[0]+Ascii[1]+Ascii[2]+str(k2)
                if k2 == 2:
                    Ascii = Ascii[0]+Ascii[2]+Ascii[1]+str(k2)
                if k2 == 3:
                    Ascii = Ascii[1]+Ascii[0]+Ascii[2]+str(k2)
                if k2 == 4:
                    Ascii = Ascii[1]+Ascii[2]+Ascii[0]+str(k2)
                if k2 == 5:
                    Ascii = Ascii[2]+Ascii[0]+Ascii[1]+str(k2)
                if k2 == 6:
                    Ascii = Ascii[2]+Ascii[1]+Ascii[0]+str(k2)
        
                lst_output.append(Ascii)
        
            str_output = ''
        
            for i in lst_output:
                r1 = str(random.randint(0,9))
                r2 = str(random.randint(0,9))
                k1 = str(random.randint(0,9))
        
                x = ''
                if k1 == '0':
                    x = i[0]+i[1]+i[2]+r1+r2
                if k1 == '1':
                    x = i[0]+i[1]+r1+i[2]+r2
                if k1 == '2':
                    x = i[0]+i[1]+r1+r2+i[2]
                if k1 == '3':
                    x = i[0]+r1+i[1]+i[2]+r2
                if k1 == '4':
                    x = i[0]+r1+i[1]+r2+i[2]
                if k1 == '5':
                    x = i[0]+r1+r2+i[1]+i[2]
                if k1 == '6':
                    x = r1+i[0]+i[1]+i[2]+r2
                if k1 == '7':
                    x = r1+i[0]+i[1]+r2+i[2]
                if k1 == '8':
                    x = r1+i[0]+r2+i[1]+i[2]
                if k1 == '9':
                    x = r1+r2+i[0]+i[1]+i[2]
        
                x += k1+i[3]
                str_output += x
        
            return str_output
        
        
        def shift(str_input):
            str_output = ''
            for i in range(len(str_input)):
                ii = int(str_input[i])
                if i%7 == 0:
                    shift = random.randint(0,9)
                    k1 = random.randint(0,4)
                    k2 = random.randint(k1+1,5)
                if k1 <= i%7 < k2:
                    ii += shift
                ii = str(ii)
                if len(ii) > 1:
                    ii = ii[1]
                if i%7 == 6:
                    str_output += (ii+str(shift)+str(k1)+str(k2))
                else:
                    str_output += ii
        
            return str_output
        def ramzgoshaei(n):
            kshift=n[len(n)-2]+n[len(n)-1]
            shift=int(n[len(n)-3])
            ot=[]
            for i in range(len(n)-5):
                e=int(n[i])
                if i>=int(kshift)//10 and i<int(kshift)%10:
                    if e-shift>=0:
                        e=e-shift
                    else:
                        e=10+(e-shift)
                    ot.append(e)
                else:
                    ot.append(e)
            s1=['123rr','12r3r','12rr3','1r23r','1r2r3','1rr23','r123r','r12r3','r1r23','rr123']
            s2=['123','132','213','231','312','321']
            k1=int(n[len(n)-5])
            w=s1[k1]
            k2=int(n[len(n)-4])
            ww=s2[k2-1]
            c=[]
            r=[]
            for j in range(len(w)):
                q=w[j]
                if q=='1':
                    c.append(ot[j])
                    r.append('1')
                elif q=='2':
                    c.append(ot[j])
                    r.append('2')
                elif q=='3':
                    c.append(ot[j])
                    r.append('3')
            z=[0]*3
            z[0]=c[ww.index(r[0])]
            z[1]=c[ww.index(r[1])]
            z[2]=c[ww.index(r[2])]
            al=[[0,4,6],[0,3,3],[0,6,3]]
            space=[0,3,2]
            if z in al:
                return 1
            elif z==space:
                return 2
            else:
                return 0
        def index(n):
            s3=[6,1,8,7,5,3,2,9,4]
            s5=[25,13,1,19,7,16,9,22,15,3,12,5,18,6,24,8,21,14,2,20,4,17,10,23,11]
            c=''
            u=''
            d=[]
            for j in range(len(n)):
                c=c+n[j]
                if (j+1)%10==0:
                    if ramzgoshaei(c)!=0:
                        x=len(d)
                        dd=[0]*x
                        if x<=9:
                            f=-1
                            for y in range(9):
                                v=s3[y]
                                if v<=x:
                                    f=f+1
                                    dd[f]=d[v-1]
                            for l in dd:
                                u=u+l
                            u=u+c
                            d=[]
                            c=''
                        else:
                            f=-1
                            for y in range(25):
                                v=s5[y]
                                if v<=x:
                                    f=f+1
                                    dd[f]=d[v-1]
                            for l in dd:
                                u=u+l
                            u=u+c
                            d=[]
                            c=''
                    else:
                        d.append(c)
                        c=''
            return u
        def fac(n):
            v=1
            for i in range(1,n+1):
                v=v*i
            return v
        def satrn(n):
            p=[]
            for i in range(n+1):
                q=fac(n)
                qq=fac(i)
                qqq=fac(n-i)
                z=int(q/(qq*qqq))
                p.append(z)
            c=''
            for j in p:
                c=c+str(j)
            return c
        def pas_kha(n):
            o=''
            d=''
            z=[]
            x=[]
            u=''
            for i in range(len(n)):
                o=o+n[i]
                d=d+n[i]
                if (i+1)%10==0:
                    if ramzgoshaei(d)==1:
                        r=o[:len(o)-10]+shift(asembly(" "))
                        z.append(r)
                        x.append(r)
                        zz=[]
                        for j in range(len(z)):
                            w=random.choice(z)
                            zz.append(w)
                            z.remove(w)
                        for t in range(len(zz)):
                            l=zz[t]
                            s=x.index(l)
                            zz[t]=l+satrn(s)+shift(asembly(" "))
                        for y in zz:
                            u=u+y
                        u=u+o[len(o)-10:]
                        o=''
                        zz=[]
                    elif ramzgoshaei(d)==2:
                        z.append(o)
                        x.append(o)
                        o=''
                    else:
                        d=''
            return u
        n = user_message
        a = asembly(n)
        b = shift(a)
        c = index(b)
        # d = pas_kha(c)
        return (c)
        
        
    if decryption_bool == True:
        def indexdecode(n):
            s3=[6,1,8,7,5,3,2,9,4]
            s5=[25,13,1,19,7,16,9,22,15,3,12,5,18,6,24,8,21,14,2,20,4,17,10,23,11]
            c=''
            u=''
            d=[]
            for j in range(len(n)):  
                c=c+n[j]
                if (j+1)%10==0: 
                    if ramzgoshaei(c)!=0:
                        x=len(d)
                        dd=[0]*x
                        if x<=9:
                            f=-1
                            for y in range(9):
                                v=s3[y]
                                if v<=x:
                                    f=f+1
                                    dd[v-1]=d[f]
                            for l in dd:
                                u=u+l
                            u=u+c
                            d=[]
                            c=''
                        else:
                            f=-1
                            for y in range(25):
                                v=s5[y]
                                if v<=x:
                                    f=f+1
                                    dd[v-1]=d[f]
                            for l in dd:
                                u=u+l
                            u=u+c
                            d=[]
                            c=''
                    else:
                        d.append(c)
                        c=''
            return u

        def ramzgoshaei2(n):
            kshift=n[len(n)-2]+n[len(n)-1]
            shift=int(n[len(n)-3])
            ot=[]
            for i in range(len(n)-5):
                e=int(n[i])
                if i>=int(kshift)//10 and i<int(kshift)%10:
                    if e-shift>=0:
                        e=e-shift
                    else:
                        e=10+(e-shift)
                    ot.append(e)
                else:
                    ot.append(e)
            s1=['123rr','12r3r','12rr3','1r23r','1r2r3','1rr23','r123r','r12r3','r1r23','rr123']
            s2=['123','132','213','231','312','321']
            k1=int(n[len(n)-5])
            w=s1[k1]
            k2=int(n[len(n)-4])
            ww=s2[k2-1]
            c=[]
            r=[]
            for j in range(len(w)):
                q=w[j]
                if q=='1':
                    c.append(ot[j])
                    r.append('1')
                elif q=='2':
                    c.append(ot[j])
                    r.append('2')
                elif q=='3':
                    c.append(ot[j])
                    r.append('3')
            z=[0]*3
            z[0]=c[ww.index(r[0])]
            z[1]=c[ww.index(r[1])]
            z[2]=c[ww.index(r[2])]
            return str(z[0]) + str(z[1]) + str(z[2])
        return ("why?")

        user_message = indexdecode(user_message)
        indef = []
        step = ''
        for i in range(len(user_message)):
            if (i)%10 == 0 and i != 0:
                indef.append(step)
                step = user_message[i]
            else:
                step += user_message[i]
        indef.append(step)

        reout = ''
        for i in indef:
            x = ramzgoshaei2(i)
            reout += chr(int(x))

        return (reout)
    
    
    
    cloudflare_bool = False
    cms_bool = False
    dns_lookup_bool = False
    find_admin_bool = False
    find_shared_dns_bool = False
    http_header_bool = False
    ip_location_bool = False
    port_scanner_bool = False
    reverse_ip_bool = False
    traceroute_bool = False
    whois_bool = False
    
    if log_position != 3:
        log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    cryptography_bool = False
    decryption_bool = False
    return "I dont understand you! Please try again. /help"



def handle_message(update,context):
    text=str(update.message.text)
    response_text=output_response(text)
    update.message.reply_text(response_text)

updater=Updater(api_key,use_context=True)
dp=updater.dispatcher

dp.add_handler(CommandHandler("start",start_command))
dp.add_handler(CommandHandler("help",help_command))
dp.add_handler(CommandHandler("help2",help2_command))

dp.add_handler(CommandHandler("sign_up",sign_up_command))
dp.add_handler(CommandHandler("sign_out",sign_out_command))
dp.add_handler(CommandHandler("log_in",log_in_command))
dp.add_handler(CommandHandler("log_out",log_out_command))

dp.add_handler(CommandHandler("edit_username",edit_username_command))
dp.add_handler(CommandHandler("edit_password",edit_password_command))
dp.add_handler(CommandHandler("cancel",cancel_command))

dp.add_handler(CommandHandler("cloudflare",cloudflare_command))
dp.add_handler(CommandHandler("cms",cms_command))
dp.add_handler(CommandHandler("dns_lookup",dns_lookup_command))
dp.add_handler(CommandHandler("find_admin",find_admin_command))
dp.add_handler(CommandHandler("find_shared_dns",find_shared_dns_command))
dp.add_handler(CommandHandler("http_header",http_header_command))
dp.add_handler(CommandHandler("ip_location",ip_location_command))
dp.add_handler(CommandHandler("traceroute",traceroute_command))
dp.add_handler(CommandHandler("port_scanner",port_scanner_command))
dp.add_handler(CommandHandler("reverse_ip",reverse_ip_command))
dp.add_handler(CommandHandler("whois",whois_command))

dp.add_handler(CommandHandler("encode",cryptography_command))
dp.add_handler(CommandHandler("decode",decryption_command))

dp.add_handler(CommandHandler("clear_history",clear_history_command))
dp.add_handler(CommandHandler("overview_history",overview_history_command))

dp.add_handler(MessageHandler(Filters.text,handle_message))

updater.start_polling()
updater.idle()


# create by SinShin company - sajad zare & shayan razavi

'''
sign_up - create a new account
sign_out - delete account
log_in - entry in account
log_out - exit from account

cloudflare - check cloudflare
cms - take cms
dns_lookup - lookup dns
find_admin - find the website admin address
find_shared_dns - find the shared dns
http_header - take http header of websites
ip_location - find ip location 
port_scanner - sacn the ports
reverse_ip - reverse ip :))
traceroute - trace the route
whois - take information of websites

clear_history - clear the URLs history
overview_history - view URLs history

edit_username - change the username
edit_password - change the password
cancel - cancel the previous command

start - none
help - none


secret tags:
encode - encrypt a text
decode - break a password
'''







