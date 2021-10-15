
from flask import Flask, request
import logging
import socket
from urllib.parse import urlparse
from flask_cors import CORS
from re import search
import whois
import requests

api = Flask(__name__)
CORS(api)
cors = CORS(api, resource={
    r"/*":{
        "origins":"*"
    }
})

command = ''
cd = ''
ls = ''
loc = ''
copy = ''
dele = ''
download = ''
msg = ''

legitweb = []

src = ["https://www.ctbcbank.com.ph/",
"https://www.dbp.ph/",
"https://www.dungganonbank.com/",
"https://www.eastwestbanker.com/",
"https://www.eastwestcorporate.com.ph/",
"https://www.equicomsavings.com/",
"https://www.landbank.com/",
"https://www.lbpiaccess.com/",
"https://www.lbp-eservices.com/",
"https://www.bdo.com.ph",
"https://www.maybank.com.ph/",
"https://www.metrobank.com.ph/",
"https://www.pacific-ace.com/bank/",
"https://www.pbcom.com.ph/",
"https://www.pnb.com.ph/",
"https://www.psbank.com.ph/",
"https://www.rcbc.com/",
"https://www.rcbconlinebanking.com/",
"https://www.robinsonsbank.com.ph/",
"https://www.securitybank.com/",
"https://www.sterlingbankasia.com/",
"https://sterlingbankonline-personal.com/",
"https://www.ucpbsavings.com/",
"https://www.unionbankph.com/",
"https://www.ucpb.com/",
"https://www.ucpb.biz/",
]

for v in src:
    v = v.replace("\n", "")
    parsed = urlparse(v)
    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed)
    res = '{uri.netloc}'.format(uri=parsed)
    legitweb.append({'url': v,'host': result, 'hostname': res, 'ip': socket.gethostbyname(res)})

log = logging.getLogger('werkzeug')
#api.logger.disabled = True
#log.disabled = True
@api.route('/try', methods=['GET'])
def out3():
    if request.method == 'GET':
        return {"data":legitweb}

@api.route('/urlch', methods=['POST'])
def out():
    if request.method == 'POST':
        try:
            content = request.get_json()
            url = content['url']
            token = content['tkn']
            if(token == '123'):
                parsed_uri = urlparse(url)
                result1 = '{uri.netloc}'.format(uri=parsed_uri)
                ip = socket.gethostbyname(result1)
                ch = {}
                ch['ip'] = ip
                for v in legitweb:
                    if v['ip'] == ip:
                        c = v
                        c['legit'] = True
                        ch = c
                ch['host'] = result1
                domain_info = whois.whois(result1)
                for key, value in domain_info.items():
                    if "whois" not in key:
                        ch[key] = value
                if "legit" in ch:
                    if ch['legit']:
                        return ch
                else:
                    ch['legit'] = False
                    return ch
            else:
                return {'message': 'Wrong token'}
        except Exception as e:
            try:
                parsed_uri = urlparse(url)
                result1 = '{uri.netloc}'.format(uri=parsed_uri)
                result1 = "www."+result1
                ip = socket.gethostbyname(result1)
                ch = {}
                for v in legitweb:
                    if v['ip'] == ip:
                        c = v
                        c['legit'] = True
                        ch = c
                ch['host'] = result1
                domain_info = whois.whois(result1)
                for key, value in domain_info.items():
                    if "whois" not in key:
                        ch[key] = value
                if "legit" in ch:
                    if ch['legit']:
                        return ch
                else:
                    ch['legit'] = False
                    return ch
            except Exception as e:
                return {"message":"error"}


@api.route("/notbankurl", methods=['POST'])
def out5():
    if request.method == 'POST':
        content = request.get_json()
        url = content['url']
        token = content['tkn']
        if(token == '123'):
            response = requests.get(url)
            if response.history:
                redlinks = []
                for resp in response.history:
                    redlinks.append({"statuscode":resp.status_code, "url": resp.url})
                return {
                    "valid":True,
                    "redirectedlinks":redlinks,
                    "finalstatus":response.status_code,
                    "finalurl":response.url
                }
            else:
                return {"valid":False}

        
if __name__ == '__main__':
    api.run(debug=True, host='0.0.0.0', port=3001)




