import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from itertools import cycle
from configparser import ConfigParser
import os

import coloredlogs
import requests

config = ConfigParser()
config.read('config.ini')

coloredlogs.install(
    fmt='%(asctime)s [%(programname)s] %(levelname)s %(message)s')


ACCOUNTS = []
PROXIES = []
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0",
}

try:
    # load settings from config file
    MAX_ATTEMPTS = config.getint('settings', 'attempts')
    MAX_WORKERS = config.getint('settings', 'workers')
    SEPARATOR = config.get('settings', 'separator')
except:
    logging.warn("invalid settings found! reverting to default settings.")

    # default settings if config not present
    MAX_ATTEMPTS = 10
    MAX_WORKERS = 10
    SEPARATOR = ";"


# load accounts
with open('accounts.txt') as f:
    for l in f:
        line = l.strip()
        if not line:
            continue

        email, password = line.split(SEPARATOR)

        if (not email or not password):
            continue

        ACCOUNTS.append({"email": email.strip(), "password": password.strip()})


# load proxies
with open('proxies.http.txt') as h, open('proxies.socks.txt') as s:
    for l in h:
        line = l.strip()
        if not line:
            continue
        PROXIES.append('http://%s' % line)
    for l in s:
        line = l.strip()
        if not line:
            continue
        PROXIES.append('socks5://%s' % line)

C_PROXIES = cycle(PROXIES) if PROXIES else None


def nextProxy():
    return next(C_PROXIES) if PROXIES else None


def activateSMTP(email, password):
    failedAttempts = 0

    proxy = nextProxy()

    # create new session
    session = requests.Session()

    # login user
    while (failedAttempts < MAX_ATTEMPTS):
        try:
            url = "https://konto.onet.pl/login.html?app_id=poczta.onet.pl.front.onetapi.pl"
            payload = {"login": email, "password": password}
            proxies = {"http": proxy, "https": proxy} if proxy else {}
            response = session.post(
                url=url, data=payload, headers=HEADERS, proxies=proxies)
        except Exception as e:
            # rotate proxy
            proxy = nextProxy()
            failedAttempts += 1
            logging.warning('user login (%s,%s) request: failed, %s' %
                            (email, proxy, str(e)))
            continue

        # validate json
        if (response.status_code != 200):
            # rotate proxy
            proxy = nextProxy()
            failedAttempts += 1
            logging.warning('user login (%s,%s) request: unexpected status, %s' %
                            (email, proxy, response.status_code))
            continue

        # success
        logging.info("user login (%s,%s) request: success" % (email, proxy))
        break

    # all login attempts failed
    if (failedAttempts >= MAX_ATTEMPTS):
        logging.warning("user login (%s,%s) request: max attempts exceed")
        return (False, email)

    # user token from login session
    token = session.cookies.get_dict().get('onet_token')

    # check if valid email/password credentials
    if not token:
        logging.warn("user login (%s,%s): invalid credentials" %
                     (email, proxy))
        return (False, email)

    # reset failed attempts
    failedAttempts = 0

    # update smtp setting
    while (failedAttempts < MAX_ATTEMPTS):
        try:
            url = "https://poczta.onet.pl/ustawienia/webmailDao.json"
            payload = {
                "data": json.dumps({
                    "blockades": {"blockades_smtp_out": 0},
                    "fn": "saveBlockades"
                })
            }
            proxies = {"http": proxy, "https": proxy} if proxy else {}
            cookies = {"onet_token": token}
            response = session.post(
                url=url, data=payload, headers=HEADERS, cookies=cookies, proxies=proxies)
        except Exception as e:
            # rotate proxy
            proxy = nextProxy()
            failedAttempts += 1
            logging.warning(
                'smtp activation (%s, %s) request: failed, %s' % (email, proxy, str(e)))
            continue

        # validate response code
        if (response.status_code != 200):
            # rotate proxy
            proxy = nextProxy()
            failedAttempts += 1
            logging.warning('smtp activation (%s, %s) request: unexpected status, %s' %
                            (email, proxy, response.status_code))
            continue

        # validate JSON
        try:
            result = response.json()
        except Exception as e:
            failedAttempts += 1
            # check if account blocked
            if ("zablokowane" in response.text):
                proxy = nextProxy()
                logging.error(
                    'smtp activation (%s, %s) request: account blocked!' % (email, proxy))
                return (False, email)
            else:
                logging.error(
                    'smtp activation (%s, %s) request: invalid JSON!, %s' % (email, proxy, str(e)))
                return (False, email)

        # check if valid activation
        if result.get('error') != 0:
            logging.warning(
                "smtp activation (%s, %s) request: unexpected response, %s" % (email, proxy, response.content))
            continue

        # success
        logging.info("smtp activation (%s, %s) request: success" %
                     (email, proxy))
        return (True, email)

    return (False, email)


if __name__ == "__main__":
    logging.info("bot started!")
    logging.info("accounts loaded: %s accounts" % len(ACCOUNTS))
    logging.info("proxies loaded: %s proxies" % len(PROXIES))

    with PoolExecutor(max_workers=MAX_WORKERS) as executor:
        passed = 0
        failed = 0
        totalAccounts = len(ACCOUNTS)
        bad_ACCOUNTS = []

        for (status, email) in executor.map(lambda a: activateSMTP(a["email"], a["password"]), ACCOUNTS):
            if status == False:
                failed += 1
                bad_ACCOUNTS.append(email)
                continue

            passed += 1

            logging.info('%s/%s processed' % (passed+failed, totalAccounts))

    # bot stats
    logging.info('accounts succeeded: %s/%s accounts' %
                 (totalAccounts-len(bad_ACCOUNTS), totalAccounts))

    # save bad accounts to text file
    if bad_ACCOUNTS:
        with open('accounts.failed.txt', 'w+') as f:
            for a in bad_ACCOUNTS:
                f.write("%s\n" % a)
        logging.info('accounts failed: %s/%s accounts' %
                     (len(bad_ACCOUNTS), totalAccounts))

    # bot end
    logging.info('bot done!')