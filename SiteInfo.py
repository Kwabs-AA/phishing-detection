import streamlit as st
import joblib
from urllib.parse import urlparse
import requests
import certifi
from requests.exceptions import SSLError
import pandas as pd
from bs4 import BeautifulSoup
import whois
import re
import socket
from selenium import webdriver
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoAlertPresentException,WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
import shutil
import json
from base64 import b64encode
from datetime import date,datetime

API_KEY = "kw80o0wg80sw4s8ck0kks40swwoowg8go44kkssc"



model, feature_names, target_name = joblib.load("model.pkl")

url=st.text_input("Please enter the link here")


if url:
    domain=urlparse(url).netloc.split(sep='.')
    st.write(domain)

    url_domain=urlparse(url).netloc

    for value in domain:
        if value.isnumeric():
            ip=1
        else:
            ip=-1
            break

    if len(url) >= 75:
        longurl_len=1
    elif len(url) <= 54:
        longurl_len=-1
    else:
        longurl_len=0

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
    if any(short in url for short in shorteners):
        shorturl=1
    else:
        shorturl=-1

    if "@" in url:
        Symbol=1
    else:
        Symbol=-1

    if url.count("//") > 1:
        redirecting=1
    else:
        redirecting=-1
    
   
    try:
        response = requests.get(url, verify=certifi.where(), timeout=5)
        if response.status_code == 200:
            protocol_used = -1  
        else:
            protocol_used = 1   
    except SSLError:
        protocol_used = 1  
    except Exception:
        protocol_used = 1  
    
    if '-' in urlparse(url).netloc:
        prefix=1 
    else:
        prefix=-1

    if urlparse(url).netloc.split('.'):
        level_of_domain=len(urlparse(url).netloc.split('.'))-2


    if level_of_domain == 1:
        subdomain=-1
    elif level_of_domain == 2:
        subdomain = 0
    else:
        subdomain=1

    html_content=requests.get(url,verify=False).text
    soup=BeautifulSoup(html_content,features="html.parser")
    icon_link=soup.find("link",rel="shortcut icon")
    if icon_link is None:
        icon_link=soup.find("link", rel="icon")
    if icon_link is None:
        icon_link=soup.find("link", rel="favicon")

    if icon_link is None:
        favicon=1
    else:
        if urlparse(url).netloc == urlparse(icon_link['href']).netloc :
            favicon=-1
        else:
            favicon=1

    #Non std Port
    preferred_ports = [80, 443]


    open_ports = []


    ports_to_check = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]

    for port in ports_to_check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((url_domain, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass  # ignore connection failures for individual ports

# Analyze after scanning all ports
    if open_ports:
        if all(port in preferred_ports for port in open_ports):
            port_status = -1  # only safe/default ports open
        else:
            port_status = 1  # suspicious (non-standard ports open)
    else:
        port_status = -1 

  
    


    links = soup.find_all('a')
    total_links = len(links)
    relative_links = 0

    for link in links:
        href = link.get('href')
        if href and not href.startswith('/'):
            relative_links += 1

    if total_links == 0:
        percentage = 0
    else:
        percentage = (relative_links / total_links) * 100

    if percentage < 22:
        url_request = -1
    elif percentage < 61:
        url_request = 0
    else:
        url_request = 1
    

    if "https" in urlparse(url).netloc:
        https_domain_url=1
    else:
        https_domain_url=-1


    domain_info=whois.whois(urlparse(url).netloc)
    if isinstance(domain_info.expiration_date,list):
        for date in domain_info.expiration_date:
            domain_expiration_date=date
    elif isinstance(domain_info.expiration_date,datetime):
        domain_expiration_date=domain_info.expiration_date

    try:
        domain_expiry_year=domain_expiration_date.year - domain_expiration_date.year
    except:
        domain_expiry_year=0

    if domain_expiry_year <=1:
        domain_reg_len=1
    else:
        domain_reg_len=-1
    
    
    iframe_value=soup.find("iframe")
    if iframe_value:
        iframe=-1
    else:
        iframe=1


    #Abnormal Url
    host_name=domain_info.name_server
    host_name=urlparse(url).netloc.split('.')
    for name in host_name:
        for value in domain:
            if name.lower() in value.lower():
                AbnormalURL = -1
            else:
                AbnormalURL = 1
    
    #website forwarding
    website_response = requests.get(url, allow_redirects=True, timeout=10,verify=False)
    num_redirects = len(website_response.history)

    if num_redirects <= 1:
        WebsiteForwarding = -1  # Legitimate
    elif 2 <= num_redirects < 4:
        WebsiteForwarding = 0   # Suspicious
    else:
        WebsiteForwarding = 1   # Phishing


    #Statusbar
    mouseover_tags=soup.find_all(onmouseover=True)
    if not mouseover_tags:
        StatusBarCust=1
    for tags in mouseover_tags:
        onmouseover_code = tags['onmouseover'].lower()
        if 'window.status' in onmouseover_code or 'status' in onmouseover_code:
            StatusBarCust=-1
        else:
            StatusBarCust=1



    #mailTo
    InfoEmail=-1
    mailto_link=soup.find_all('a',href=True)
    for link in mailto_link:
        if 'mailto' in link['href'].lower():
            InfoEmail=1
    
    if re.search(r'\bmail\s*\(', soup.text, re.IGNORECASE):
        InfoEmail = 1


    #Disabled right click
    driver = webdriver.Chrome()
    driver.get(url)
    actions = ActionChains(driver)

    try:
        actions.context_click(driver.find_element(By.TAG_NAME, 'body')).perform()
        # Try to switch to an alert (if right-click triggers one)
        alert = driver.switch_to.alert
        _ = alert.text  # Attempt to read the alert to trigger exception if not present
        is_disabled = 1
    except NoAlertPresentException:
        is_disabled = -1
    finally:
        driver.quit()

    
    
    #serverFormHandler
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        action_domain=urlparse(action).netloc

        if action == "" or action.strip().lower() =="about:blank":
            ServerFormHandler=-1
        elif action_domain == urlparse(url).netloc:
            ServerFormHandler=0
        else:
            FormHandler=1
    
    if not forms:
        ServerFormHandler=1


    #age of domain
    today=date.today()
    if isinstance(domain_info.creation_date, list):
        for date in domain_info.creation_date:
            if isinstance(date, datetime):
                domain_creation_date=date
    elif isinstance(domain_info.creation_date, datetime):
        domain_creation_date=domain_info.creation_date

    if domain_info.creation_date:
        domain_age_in_months = (today.year - domain_creation_date.year) * 12 + (today.month - domain_creation_date.month)
        if domain_age_in_months <=6 :
            domain_age_value=1
        else:
            domain_age_value=-1
    else:
        domain_age_value=1
    

   #DNS RECORD
    if not domain_info.domain_name:
        DNSRecording=1
    else:
        DNSRecording=-1
    
    #url anchor
    for link in links:
        href=link.get('href')
        anchor_link=0
        different_anchor_link=0
        dummy_link=['#','#content','#skip','javascript:void(0)', 'javascript::void(0)']
        if href:
            if not urlparse(href).netloc==urlparse(url).netloc or href.lower() in dummy_link:
                anchor_link+=1

        anchor_percentage= (anchor_link/total_links)*100

        if anchor_percentage <=31:
            anchor_url=-1
        elif anchor_percentage <= 67:
            anchor_url=0
        else:
            anchor_url=1
    else:
        anchor_url=-1

    meta_links=soup.find_all('meta')
    script_links=soup.find_all('script')
    head_links=soup.find_all('link')
    total_meta_links=len(meta_links)
    total_script_link=len(script_links)
    total_head_links=len(head_links)
    alt_meta = alt_script = alt_head_link = 0
   
    for link in meta_links:
        meta_link=link.get('href')
        meta_domain=urlparse(meta_link).netloc

        if meta_link and meta_domain != url_domain:
            alt_meta +=1  
    for link in script_links:
        script_link=link.get('href')
        script_domain=urlparse(script_link).netloc

        if script_link and script_domain != url_domain:
            alt_script +=1
       
    for link in head_links:
        head_link=link.get('href')
        head_link_domain=urlparse(head_link).netloc

        if head_link and head_link_domain != url_domain:
            alt_head_link +=1
    
    total_LinkInScriptTags=((alt_script+alt_meta+alt_head_link)/(total_head_links+total_meta_links+total_script_link)*100)

    if total_LinkInScriptTags <= 17:
        LinkInScriptTags=-1
    elif total_LinkInScriptTags <=81:
        LinkInScriptTags=0
    else:
        LinkInScriptTags=1

    driver = None
    UsingPopupWindow = -1

    try:
        # Use webdriver-manager to automatically handle ChromeDriver
        options = ChromeOptions()
        options.add_argument("--headless")
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        # Rest of your code...
        driver.get(url)
        time.sleep(5)
        
        main_window = driver.current_window_handle
        all_windows = driver.window_handles
        
        if len(all_windows) > 1:
            UsingPopupWindow = 1
            
    except Exception as e:
        print(f"WebDriver error: {e}")
        UsingPopupWindow = 0
    finally:
        if driver:
            driver.quit()

    #Page Rank
    domcomp_rank = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={url_domain}"
    headers = {"API-OPR": API_KEY}

    response = requests.get(domcomp_rank, headers=headers)
    data = response.json()

    if "response" in data and data["response"]:
        rank = data['response'][0].get('rank')
        page_rank = data["response"][0].get("page_rank_integer", None)
        if page_rank < 0.2:
            PageRank=1
        else:
            PageRank=-1
        if rank is not None:
            rank=int(rank)
            if rank < 100000:
                Website_traffic=-1
            elif rank > 100000:
                Website_traffic=0
            else:
                Website_traffic=1
        else:
            Website_traffic=0
    else:
       Website_traffic=0
        

        


    #Google Index
    api_key = "AIzaSyCMiMEdX4hlGHx4Px51vmDujkZUSjqNPPA"
    cx = "b2291506cf07d47bf"


    query = f"site:{url_domain}"
    endpoint = "https://www.googleapis.com/customsearch/v1"

    params = {
            "key": api_key,
            "cx": cx,
            "q": query
        }

    index_response = requests.get(endpoint, params=params)
    data = index_response.json()

    if 'items' in data:
        GoogleIndex=-1
    else:
        GoogleIndex=1

    #links pointing to pages
    

    profiler_url = f'https://www.openlinkprofiler.org/r/{url_domain}'
    headers = {'User-Agent': 'Mozilla/5.0'}

    Link_response = requests.get(profiler_url, headers=headers)
    soup = BeautifulSoup(Link_response.text, 'html.parser')

    element = soup.find('div', class_='number-box')

    if element:
        backlinks_text = element.get_text(strip=True)
        backlinks_number = ''.join(filter(str.isdigit, backlinks_text))
        backlinks = int(backlinks_number) if backlinks_number else 0
    else:
        backlinks = 0

    if backlinks == 0:
        NumberOfLinksPointingToPage = 1 
    elif backlinks <= 2:
        NumberOfLinksPointingToPage = 0  
    else:
        NumberOfLinksPointingToPage = -1  



  #StatsReport
 

    api_key = "60d30c932bf682a40854faeab84bcd8bbe0053088264dbea40ad356030bc55e0"

    url = f"https://www.virustotal.com/api/v3/domains/{url_domain}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    # You can examine different verdicts
    malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']

    if malicious_count >= 5:
        StatsReport = 1 
    else:
        StatsReport = -1  
    
   
    
    
    
    
    website_variables=[[
        ip,
        longurl_len,
        shorturl,
        Symbol,
        redirecting,
        prefix,
        subdomain,
        protocol_used,
        domain_reg_len,
        favicon,
        port_status,
        https_domain_url,
        url_request,
        anchor_url,
        LinkInScriptTags,
        ServerFormHandler,
        InfoEmail,
        AbnormalURL,
        WebsiteForwarding,
        StatusBarCust,
        is_disabled,
        UsingPopupWindow,
        iframe,
        domain_age_value,
        DNSRecording,
        Website_traffic,
        PageRank,
        GoogleIndex,
        NumberOfLinksPointingToPage,
        StatsReport,
        ]]
    
    prediction_score=model.predict(website_variables)

    st.write("Prediction:", "Phishing ❌ " if prediction_score== 1 else "Safe ✅")




