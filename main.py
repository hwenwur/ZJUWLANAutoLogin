import time
import re
import json
import os
import hashlib
import hmac
import base64
import js2py
import requests


def cut_text(origin, start, end):
    """
    >>> cut_text("a=123&b=456", "a=", "&")
    '123'
    """
    s = origin.index(start) + len(start)
    origin = origin[s:]
    e = origin.index(end)
    return origin[:e]


def md5sum(msg, key):
    """
    >>> md5sum(b"1", b"2")
    '3b1066c288f9c6b01d57ff6a6f0cb9cc'

    :param msg:
    :param key:
    :return:
    """
    md5 = hmac.new(key, digestmod=hashlib.md5)
    md5.update(msg)
    return md5.hexdigest()


def sha1sum(msg):
    """
    >>> sha1sum(b"1")
    '356a192b7913b04c54574d18c28d46e6395428ab'

    :param msg:
    :param key:
    :return:
    """
    sha1 = hashlib.sha1()
    sha1.update(msg)
    return sha1.hexdigest()


def x_encode(str_, key) -> str:
    """
    wrapper for javascript function
    :param str_:
    :param key:
    :return:
    """
    with open("xencode.js") as fp:
        script = fp.read()
        xencode = js2py.eval_js(script)
        return xencode(str_, key)


def base64encode_custom(text: str) -> str:
    """
    >>> base64encode_custom("1")
    '9+=='

    自定义的base64，字符集顺序和标准版有区别，字符串编码方式也略有区别
    :param text:
    :return:
    """
    bs = list(text)
    bs = map(ord, bs)
    bs = bytes(bs)
    std_alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    custom_alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
    tmp = base64.b64encode(bs).decode()
    ret = ""
    for x in tmp:
        if x == "=":
            ret += "="
        else:
            i = std_alpha.index(x)
            ret += custom_alpha[i]
    return ret


def checksum(params, challenge):
    """
    计算校验和
    :param params:
    :param challenge:
    :return:
    """
    cksum = challenge + params["username"] + \
        challenge + params["password"][5:] + \
        challenge + params["ac_id"] + \
        challenge + params["ip"] + \
        challenge + params["n"] + \
        challenge + params["type"] + \
        challenge + params["info"]
    return sha1sum(cksum.encode())


def calc_info(data: str, challenge):
    """
    >>> calc_info("{}", "22")
    '{SRBX1}veSqleRrlN/='

    :param data:
    :param challenge:
    :return:
    """
    x = x_encode(data, challenge)
    return "{SRBX1}" + base64encode_custom(x)


def check_login_need():
    """
    :return: 需要登录，返回True；不需要登录，返回False；无网络，raise
    """
    url = "http://connect.rom.miui.com/generate_204"
    r = requests.get(url, allow_redirects=False)
    # 返回 204 说明网络正常
    # 返回 302 通常是被网关重定向到了登录页面
    if r.status_code == 302:
        location = r.headers.get("Location", "")
        if "ZJUWLAN" in location:
            return True
    elif r.status_code == 204:
        # 网络一切正常
        return False
    else:
        # 其他情况，可能是非ZJUWLAN，但是也需要登录
        # 以后处理
        return False


def get_challenge(base_url, username, ip):
    timestamp = int(time.time() * 1000)
    url = base_url + "/cgi-bin/get_challenge"
    params = {
        "callback": "jQuery1124026320068192169077_%d" % timestamp,
        "username": username,
        "ip": ip,
        "_": timestamp
    }
    r = requests.get(url, params=params)
    pattern = '"error":\\s*"(.*?)"'
    ret = re.findall(pattern, r.text)
    if ret and ret[0] == "ok":
        pattern = '"challenge":\\s*"(.*?)"'
        challenge = re.findall(pattern, r.text)
        return challenge[0]
    else:
        print("Failed to login")
        print(r.text)


def login(username, password):
    # step 1: Get 'challenge'
    url = "http://connect.rom.miui.com/generate_204"
    r = requests.get(url)
    challenge = None
    if r.status_code == 200 and "ZJUWLAN" in r.url:
        base_url = cut_text(r.url, "http://", "/")
        base_url = "http://" + base_url
        ip = cut_text(r.url, "ip=", "&")
        challenge = get_challenge(base_url, username, ip)
    else:
        raise RuntimeError
    # step 2: login
    info = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": "2",
        "enc_ver": "srun_bx1"
    }
    password = "{MD5}" + md5sum(password.encode(), challenge.encode())
    params = {
        "callback": "jQuery1124026320068192169077_%d" % int(time.time() * 1000),
        "action": "login",
        "username": username,
        "password": password,
        "ac_id": "2",
        "ip": ip,
        "chksum": "",
        "info": calc_info(json.dumps(info), challenge),
        "n": "200",
        "type": "1",
        "os": "Windows 10",
        "name": "Windows",
        "double_stack": "0",
        "_": int(time.time() * 1000)
    }
    params["chksum"] = checksum(params, challenge)
    r = requests.get(base_url + "/cgi-bin/srun_portal", params=params)
    resp = cut_text(r.text + "EOF", "(", ")EOF")
    resp = json.loads(resp)
    if str(resp["ecode"]) == "0":
        print("[INFO] 登录成功：%s" % resp["client_ip"])
    elif resp["ecode"] == "E2901":
        print("[ERROR] 密码错误")
        print("[ERROR] " + resp["error_msg"])
    else:
        print("[ERROR] 登录失败: " + resp["ecode"])
        print("[ERROR] " + resp["error_msg"])


def main():
    if check_login_need():
        user = os.environ["ZJU_USER"]
        passwd = os.environ["ZJU_PASS"]
        login(user, passwd)
    else:
        print("[INFO] WLAN不需要登录")


if __name__ == '__main__':
    main()
