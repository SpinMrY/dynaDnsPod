import os
import re
import json
import time
import email
import socket
import smtplib
import requests
import subprocess
from email import encoders
from email.header import Header
from email.mime.text import MIMEText

# dnspod api

login_token = 'xxx,xxx'  # api_id,api_token
sub_domain = 'xxx'
domain_ = 'xxx.xxx'
record_line_id = 'xxxxxxx'
record_id = 'xxxxxxx'
req_headers = {'user-agent': 'dynaDnsPod/0.0.1 (spinmry@126.com)'}

# email server settings
SMTPServer = 'smtp.xxx.com'
master = 'xxx@xxx.com'
email_user = 'xxx@xxx.com'
email_passwd = 'xxxxxx'


def get_record_info():
    api_url = 'https://dnsapi.cn/Record.List'
    api_payload = {
        'login_token': login_token,
        'domain': domain,
        'sub_domain': sub_domain,
        'record_type': "A",
        'format': 'json'
        # 'record_line_id':record_line_id
    }
    res = requests.post(api_url, headers=req_headers, data=api_payload)
    res_json = json.dumps(res.json(), indent=2)
    enc_json = json.loads(res_json)
    print(res_json)
    res_ip = enc_json['records'][0]['value']
    return res_ip


def get_server_record_ip():  # through ping
    ping_str = subprocess.getoutput(
        'ping ' + sub_domain + '.' + domain + ' -c 1')
    ip = re.findall(r'\d+.\d+.\d+.\d+', ping_str)
    return ip[0]


def get_local_ip():
    res = requests.get("https://myip.ipip.net")
    ip = re.findall(r'\d+.\d+.\d+.\d+', res.text)
    return ip[0]


def SendEmail(subject, msgstr):
    msg = MIMEText(msgstr, 'plain', 'utf-8')
    msg['Form'] = user
    msg['To'] = master
    msg['Subject'] = subject
    sser = smtplib.SMTP(SMTPServer)
    try:
        sser.login(email_user, email_passwd)
        print('Login successfully!')
        sser.sendmail(user, [master], msg.as_string())
        print('Processed successfully')
    except smtplib.SMTPException as e:
        print(e)
    finally:
        sser.close()


def modify_dns_record():
    api_url = 'https://dnsapi.cn/Record.Modify'
    if get_record_info() == get_local_ip():
        print('Failed to modify record ip:Record IP is already local IP!')
        return False
    api_payload = {
        'login_token': login_token,
        'domain': domain,
        'record_id': record_id,
        'value': get_local_ip(),
        'sub_domain': sub_domain,
        'record_type': "A",
        'record_line_id': record_line_id,
        'format': 'json'
    }
    res = requests.post(api_url, headers=req_headers, data=api_payload)
    res_json = json.dumps(res.json(), indent=2)
    print(res_json)

    enc_json = json.loads(res_json)
    res_status = enc_json['status'][0]['code']
    print("Status:%d" % res_status)
    if res_status == '1':
        return True
    else:
        return False


def main():
    try:
        while True:
            local_ip = get_local_ip()
            server_ip = get_server_record_ip()
            if local_ip == server_ip:
                print("IP is already in use! %s" % local_ip)
            else:
                print(
                    "Local IP has changed!\nLocal IP:%s\nRecord IP:%s" %
                    (local_ip, server_ip))
                success = modify_dns_record()
                if success:
                    subject = "Record IP has modified!"
                    msgstr = "Record of domain \'%s.%s\' has been updated!\nRecord IP:%d\nServer Local IP:%d " % (
                        sub_domain, domain, get_record_info(), get_local_ip())
                    SendEmail(subject, msgstr)
                else:
                    subject = "Failed to modify record IP!"
                    msgstr = "Failed to modify record of domain \'%s.%s\'!\nRecord IP:%d\nServer Local IP:%d " % (
                        sub_domain, domain, get_record_info(), get_local_ip())
                    SendEmail(subject, msgstr)
            time.sleep(600)
    except BaseException:
        print("Something went wrong")


if __name__ == '__main__':
    main()
