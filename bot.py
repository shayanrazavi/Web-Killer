from telegram.ext import *
import random

api_key="1982384940:AAFlNGZk7kK7cEo61paPnFCcTH5_JHh-lCk"

known_user = False

log_position = 0
sign_position = 0

change_username = False
change_password = False

contact_info = {}
kown_persons = [{'username':'shayan86', 'password':'webkiller86', 'history':['https://icons8.com/']}]
pass_person = [{'username':'shayan86', 'password':'webkiller86', 'history':['https://icons8.com/']}]

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
    return "Under Construction..."

def cms(url):
    return "Under Construction..."

def dns_lookup(url):
    return "Under Construction..."

def find_admin(url):
    return "Under Construction..."

def find_shared_dns(url):
    return "Under Construction..."

def http_header(url):
    return "Under Construction..."

def ip_location(url):
    return "Under Construction..."

def port_scanner(url):
    return "Under Construction..."

def reverse_ip(url):
    return "Under Construction..."

def traceroute(url):
    return "Under Construction..."

def whois(url):
    return "Under Construction..."





def start_command(update,context):
    global sign_position, log_position, contact_info
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    known_user = False
    log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    contact_info = {}
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
/overwiew_history - view URLs history

/cancel - cancel the previous command'''
    update.message.reply_text(start_message)

def help_command(update,context):
    global known_user
    if known_user == False:
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
/overwiew_history - view URLs history

/cancel - cancel the previous command'''
        update.message.reply_text(help_message)
        
    else:
        secret_help_message = '''Welcome to Encryption system

You can control me by sending these commands:

Secret tags:
/encode - encrypt a text
/decode - break a password

/help /help2'''
        update.message.reply_text(secret_help_message)
        
def sign_up_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("Alright, How are we going to call you? Please choose a user name for your account.")
    
def sign_out_command(update,context):
    global sign_position, log_position, contact_info, known_pesons
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
    
    if log_position == 3:
        log_position = 0
        sign_position = 0
        for i in kown_persons:
            if i == contact_info:
                known_pesons.remove(i)
        contact_info = {}
        known_user = False
        update.message.reply_text("Success! Your account has been deleted. /help")
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in to your account before you can sign out. /log_in /sign_up")
    
def log_in_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("Please enter your username:")
    
def log_out_command(update,context):
    global sign_position, log_position, contact_info, known_user
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
    
    if log_position == 3:
        contact_info = {}
        log_position = 0
        sign_position = 0
        known_user = False
        update.message.reply_text("Success! You are logged out. /help")
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can log out. /log_in /sign_up")

        

def edit_username_command(update,context):
    global sign_position, log_position, contact_info
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    
    if log_position == 3:
        change_username = True
        
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
    change_password = False

def edit_password_command(update,context):
    global sign_position, log_position, contact_info
    global cloudflare_bool, cms_bool, dns_lookup_bool, find_admin_bool, find_shared_dns_bool, http_header_bool, ip_location_bool, port_scanner_bool, reverse_ip_bool, traceroute_bool, whois_bool, change_username, change_password
    
    if log_position == 3:
        change_password = True
        
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
    change_password = False

def cancel_command(update,context):
    global sign_position, log_position, contact_info
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

        
        
def cloudflare_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def cms_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def dns_lookup_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def find_admin_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def find_shared_dns_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def http_header_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def ip_location_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def port_scanner_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def reverse_ip_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def traceroute_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")

def whois_command(update,context):
    global sign_position, log_position, contact_info
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
    
    update.message.reply_text("please enter the adress of site:")
    
    
    
    
    
def cryptography_command(update,context):
    global sign_position, log_position, contact_info
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
    
    change_username = False
    change_password = False
    
    if known_user == True:
        cryptography_bool = True
        update.message.reply_text('Please enter your message:')
def decryption_command(update,context):
    global sign_position, log_position, contact_info
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
    
    change_username = False
    change_password = False
    if known_user == True:
        decryption_bool = True
        update.message.reply_text('Please enter your password:')
        
        
def clear_history_command(update,context):
    global sign_position, log_position, contact_info
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
    
    change_username = False
    change_password = False
    
    if log_position == 3:
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'] = []
        contact_info['history'] = []
        known_user = False
            
        update.message.reply_text(overview)
    
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can clear history. /log_in /log_out")

    
def overview_history_command(update,context):
    global sign_position, log_position, contact_info
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
    
    change_username = False
    change_password = False
    
    if log_position == 3:
        history = contact_info['history']
        overview = ''
        for i in history:
            overview += (i + '\n')
            
        update.message.reply_text(overview)
    
    else:
        log_position = 0
        sign_position = 0
        update.message.reply_text("Error, you must log in or sign in to your account before you can view history. /log_in /log_out")


        
def output_response(text_input):
    global sign_position, log_position, contact_info
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
        known_pesons.append(contact_info)
        return ("Success! Your account is build. /help")
        
    if log_position == 1:
        check = False
        for i in known_pesons:
            if i['username'] == user_message:
                check = True
        
        last_user_message = user_message
        
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
        for i in known_pesons:
            if i['username'] == last_user_message and i['password'] == user_message:
                check = True
                save_history.extend(i['history'])
                if i in pass_person:
                    known_user = True
                
        if check == True:
            contact_info['password'] = user_message
            contact_info['history'] = save_history
            log_position = 3
            return (f"Success! Hello {user_name}, Welcome to SinShin /help")
        else:
            log_position = 2
            return ("Wrong! Please try again:")
            
    if change_username == True:
        for i in known_pesons:
            if i['username'] == contact_info['username'] and i['password'] ==  contact_info['password']:
                known_pesons.remove(i)
                
        contact_info['username'] = user_message
        change_username = False
        known_pesons.append(contact_info)
        return ("Success! Your username has been changed. /help")
         
    if change_password == True:
        for i in known_pesons:
            if i['username'] == contact_info['username'] and i['password'] ==  contact_info['password']:
                known_pesons.remove(i)
        
        contact_info['password'] = user_message
        known_pesons.append(contact_info)
        change_password = False
        return ("Success! Your password has been changed. /help")
        
    if cloudflare_bool == True:
        output = cloudflare(user_message)
        cloudflare_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if cms_bool == True:
        output = cms(user_message)
        cms_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if dns_lookup_bool == True:
        output = dns_lookup(user_message)
        dns_lookup_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if find_admin_bool == True:
        output = find_admin(user_message)
        find_admin_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if find_shared_dns_bool == True:
        output = find_shared_dns(user_message)
        find_shared_dns_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if http_header_bool == True:
        output = http_header(user_message)
        http_header_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if ip_location_bool == True:
        output = ip_location(user_message)
        ip_location_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if port_scanner_bool == True:
        output = port_scanner(user_message)
        port_scanner_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if reverse_ip_bool == True:
        output = reverse_ip(user_message)
        reverse_ip_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if traceroute_bool == True:
        output = traceroute(user_message)
        traceroute_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
        contact_info['history'].append(user_message)
        return (output)
    
    if whois_bool == True:
        output = whois(user_message)
        whois_bool = False
        for i in kown_persons:
            if i == contact_info:
                known_pesons[i]['history'].append(user_message)
                
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
            
        indef = []
        step = ''
        for i in range(len(user_message)):
            if (i+1)%10 == 0:
                indef.append(step)
                step = ''
            else:
                step += user_message[i]
        
        reout = ''
        for i in indef:
            x = ramzgoshaei(i)
            reout += chr(x)
            
        return (reout)
    
    
    
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
    
    log_position = 0
    sign_position = 0
    change_username = False
    change_password = False
    return "I dont understand you! Please try again. /help"



def handle_message(update,context):
    text=str(update.message.text)
    response_text=output_response(text)
    update.message.reply_text(response_text)

updater=Updater(api_key,use_context=True)
dp=updater.dispatcher

dp.add_handler(CommandHandler("start",start_command))
dp.add_handler(CommandHandler("help",help_command))

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







