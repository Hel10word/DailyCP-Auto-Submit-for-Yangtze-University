import requests
import json
import io
import random
import time
import re
import pyDes
import base64
import uuid
import sys
import os
import hashlib
import smtplib
from email.mime.text import MIMEText
from Crypto.Cipher import AES

userinfo=""
# 获取用户信息以及表单信息
with open("userInfo.json",encoding = 'utf-8') as info :
    userinfo = json.load(info)

class DailyCP:
    def __init__(self, schoolName="长江大学"):
        self.key = "b3L26XNL"  # dynamic when app update
        self.session = requests.session()
        self.host = ""
        self.loginUrl = ""
        self.isIAPLogin = True
        self.extension = {
            "lon": userinfo["lon"],
            "model": "ZBF",
            "appVersion": "8.2.14",
            "systemVersion": "10.0.0",
            "userId": userinfo["username"],
            "systemName": "android",
            "lat": userinfo["lat"],
            "deviceId": str(uuid.uuid1())
        }
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json;charset=UTF-8',
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 9; en-us; Redmi K20 Pro Build/PKQ1.181121.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/71.0.3578.141 Mobile Safari/537.36 XiaoMi/MiuiBrowser/12.8.25",
            "Pragma": "no-cache",
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': self.DESEncrypt(json.dumps(self.extension)),
            'extension': '1',
            'Connection': 'Keep-Alive'
        })

        self.setHostBySchoolName(schoolName)

    # DES加密
    def DESEncrypt(self,s):
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = pyDes.des(self.key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    # 获取学校地址
    def setHostBySchoolName(self, schoolName):
        self.loginUrl = "https://yangtzeu.campusphere.net/wec-portal-mobile/client"
        self.host = "yangtzeu.campusphere.net"


    def request(self, url: str, body=None, parseJson=True, JsonBody=True, Referer=None):
        url = url.format(host=self.host)
        if Referer != None:
            self.session.headers.update({"Referer": Referer})
        if body == None:
            ret = self.session.get(url)
        else:
            self.session.headers.update(
                {"Content-Type": ("application/json" if JsonBody else "application/x-www-form-urlencoded")})
            ret = self.session.post(url, data=(
                json.dumps(body) if JsonBody else body))
        if parseJson:
            return json.loads(ret.text)
        else:
            return ret

    def login(self, username, password, captcha=""):
        if "campusphere" in self.loginUrl:
            return self.loginIAP(username, password, captcha)
        else:
            print("login失败")

    def loginIAP(self, username, password, captcha=""):
        ret = self.session.get(
            "https://{host}/iap/login?service=https://{host}/portal/login".format(host=self.host)).url
        client = ret[ret.find("=")+1:]
        ret = self.request("https://{host}/iap/security/lt",
                           "lt={client}".format(client=client), True, False)
        client = ret["result"]["_lt"]

        body = {
            "username": username,
            "password": password,
            "lt": client,
            "captcha": captcha,
            "rememberMe": "true",
            "dllt": "",
            "mobile": ""
        }
        ret = self.request("https://{host}/iap/doLogin", body, True, False)
        if ret["resultCode"] == "REDIRECT":
            self.session.get(ret["url"])
            return True
        else:
            return False

    # 获取最新未签到任务
    def getUnSignedTasks(self):
        res = self.session.post(
            url='https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay'.format(host=self.host),data=json.dumps({}))
        print(res.json()['datas'])
        unSignedTasks = res.json()['datas']['unSignedTasks']
        if len(unSignedTasks) < 1:
            print('当前没有未签到任务')
            try_send('当前没有未签到任务')
            exit(-1)
        latestTask = unSignedTasks[0]
        print(latestTask)
        return {
            'signInstanceWid': latestTask['signInstanceWid'],
            'signWid': latestTask['signWid']
        }

    # 获取签到任务详情
    def getDetailTask(self, params):
        res = self.session.post(
            url='https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance'.format(host=self.host), data=json.dumps(params))
        data = res.json()['datas']
        return data

    def fillForm(self, task):
        form = {}
        form['signPhotoUrl'] = ''
        if task['isNeedExtra'] == 1:
            extraFields = task['extraField']
            extraFieldItemValues = []
            for i in range(0, len(extraFields)):
                default = userinfo["matchForm"][i]
                extraField = extraFields[i]
                
                if default['title'] != extraField['title']:
                    print("表单需求又TM变了！")
                    try_send("表单需求又TM变了！")
                    exit(-1)
                extraFieldItems = extraField['extraFieldItems']
                for extraFieldItem in extraFieldItems:
                    if extraFieldItem['content'] == default['value']:
                        extraFieldItemValue = {'extraFieldItemValue': default['value'],
                                            'extraFieldItemWid': extraFieldItem['wid']}
                        extraFieldItemValues.append(extraFieldItemValue)
            print('\n\n\n\n\n')
            print(extraFieldItemValues)
            form['extraFieldItems'] = extraFieldItemValues
        form['signInstanceWid'] = task['signInstanceWid']
        form['longitude'] = userinfo["lon"]
        form['latitude'] = userinfo["lat"]
        form['isMalposition'] = task['isMalposition']
        form['abnormalReason'] = ''
        form['position'] = userinfo["address"]
        form['uaIsCpadaily'] = 'true'
        form['signVersion'] = '1.0.0'
        return form

    # 提交请求
    def autoComplete(self):
        self.session.headers.update({"Content-Type": "application/json; charset=utf-8"})
        signList = self.getUnSignedTasks()
        task = self.getDetailTask(signList)
        form = self.fillForm(task)

        res = self.session.post(url='https://{host}/wec-counselor-sign-apps/stu/sign/submitSign'.format(host=self.host), headers = self.session.headers, data=json.dumps(form))
        message = res.json()['message']
        # 打印信息
        print("====")
        print(self.session.headers)
        print("====")
        print(message)
        try_send(message)


#邮件服务
def try_send(text):
    try:
        message = MIMEText(_text=text, _subtype='plain', _charset='utf-8')
        message['Subject'] = "今日校园打卡情况"
        
        smtpObj = smtplib.SMTP_SSL(host=userinfo["smtp_server"], port=465)
        smtpObj.login(user=userinfo["sender"], password=userinfo["pass_word"])
        smtpObj.sendmail(from_addr=userinfo["sender"], to_addrs=userinfo["receivers"], msg=message.as_string())
        print("sent email successfully")
        smtpObj.quit()
    except smtplib.SMTPException as e:
        print(f"failed: {e}")

def main_handler():
    app = DailyCP()
    if not app.login(userinfo["username"], userinfo["password"]):
        exit()
    app.autoComplete()
    
main_handler()
