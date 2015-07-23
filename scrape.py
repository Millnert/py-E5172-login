#!/usr/bin/env python
# Author: Martin Millnert <martin@millnert.se>, 2015

""" Scrapes a E5172S-22 Huawei CPE's webpage to retrieve bytes
downloaded / uploaded """

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64
import urllib  # For quote_plus
import urllib2
import ast


def get_config(configfile):
    """ Returns the configuration in configfile.
    Should be on format:
    username = $username
    password = $password
    url = $url
    """
    conf = open(configfile, 'r')
    buf = conf.readlines()
    username, password, url = None, None, None
    for line in buf:
        linesplit = line.split()
        if len(linesplit) == 2 and linesplit[0] == 'username':
            username = line.split()[1]
        if len(linesplit) == 2 and linesplit[0] == 'password':
            password = line.split()[1]
        if len(linesplit) == 2 and linesplit[0] == 'url':
            url = line.split()[1]
    return username, password, url


def get_cryptparams(url):
    """ Retrives var modulus; var exponent from $url/js/rsa.js """
    fullurl = url + "/js/rsa.js"
    urlfile = urllib2.urlopen(fullurl)
    modulus, pubexp = None, None

    doing_modulus = False
    for line in urlfile:
        if doing_modulus:
            if line.find('\t\t\t +"') >= 0:
                modulus += line.split('"')[1]
            else:
                doing_modulus = False
        if line.find("var modulus = ") >= 0:
            modulus = line.split('"')[1]
            doing_modulus = True
        if line.find("publicExponent") >= 0:
            pubexp = line.split('"')[1]
            urlfile.close()
            break
    long_modulus = long(modulus, 16)
    long_pubexp = long(pubexp, 16)
    return long_modulus, long_pubexp


def make_rsa_b64_password(password, modulus, exponent):
    """ Runs the plain text password through RSA -> base64."""
    phase_1 = rsa_password(password, modulus, exponent)
    phase_2 = b64_password(phase_1)
    return phase_2


def make_rsa_b64_urlencode_password(password, modulus, exponent):
    """ Runs the plain text password through RSA -> base64 -> urlencode."""
    phase_1 = rsa_password(password, modulus, exponent)
    phase_2 = b64_password(phase_1)
    phase_3 = urlencode_password(phase_2)
    return phase_3


def rsa_password(password, modulus, exponent):
    """ RSA encodes the password using given modulus and exponent."""
    rsa_n = modulus
    rsa_e = exponent
    tup = (rsa_n, rsa_e)
    rsa_key = RSA.construct(tup)
    cipher = PKCS1_v1_5.new(rsa_key)
    ciphertext = cipher.encrypt(password)
    return ciphertext


def b64_password(cryptpassword):
    """ Simply baes64 encodes a crypted password
    Note: OpenSSL requires newline every 64 chars"""
    b64encoded_password = base64.b64encode(cryptpassword)
    return b64encoded_password


def urlencode_password(b64cryptpassword):
    """ urlencodes a b64 cryptpassword """
    urlencoded_password = urllib.quote_plus(b64cryptpassword)
    return urlencoded_password


def do_login(url, username, password):
    """ Perform a login to the router """
    req = urllib2.Request(url + "/index/login.cgi")
    req.add_header('Cookie', 'Language=en_US; Username=foofoo')
    data = "Username=%s&Password=%s" % (username, password)
    response = urllib2.urlopen(req, data)
    cookie = response.headers.get('Set-Cookie')
    response.close()
    return cookie


def do_load_overview(url, cookie):
    """ Loads the overview page after sending a login request """
    req = urllib2.Request(url + "/html/status/overview.asp")
    req.add_header('cookie', cookie)
    response = urllib2.urlopen(req)

    # wanIPDNS, WanStatistics, wlanMAC
    # wlanStatistics, wlanErrStat
    # LANStatistics,
    wan_stats = None
    for line in response:
        # print(line)
        if line.find("WanStatistics") >= 0:
            data = line.lstrip('WanStatistics = ').rstrip(';\n')
            wan_stats = ast.literal_eval(data)
    response.close()
    return wan_stats


def main():
    """ The main function that retrieves the data. """
    configfile = "scrape.conf"
    username, password, url = get_config(configfile)
    mod, pub = get_cryptparams(url)
    pwd = make_rsa_b64_password(password, mod, pub)
    pwd_quoted = urllib.quote_plus(pwd)
    cookie = do_login(url, username, pwd_quoted)
    stats = do_load_overview(url, cookie)
    print(stats)

if __name__ == '__main__':
    main()
