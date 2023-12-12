#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from urllib3.exceptions import NewConnectionError, MaxRetryError, ReadTimeoutError
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from lib.crawler import Browser, Crawler
from lib.wcde import WCDE

import traceback
import argparse
import requests
import logging
import random
import string
import json
import time
import sys
import os
import re


# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================


class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

# Statistics dictionary
statistics = {
    'site':         '',
    'cors':         False,
    'vulnerable':   False,
    'wildcard':     False,
    'credentials':  False,
    'vulnerable_urls':  {},
    'variations':       []
}

# network dictionary
network = {}

# List of URLs to test for CORS misconfigurations
urls_to_test = {}
headers_to_test = {}
variations_to_test  = []

# List of URLs already tested for CORS misconfigurations
tested = []

browser = Browser()

# Logging
logging.basicConfig()
logger = logging.getLogger('cors')
logger.setLevel(logging.INFO)

# CONSTANTS
DEBUG = True
SITE  = ''
MAX_DEFAULT   = 10

LOGS        = 'logs'
STATS       = 'stats'
NETWORK     = 'network'

# Regex to avoid requesting URLs that might cause a logout
LOGOUT_BLACKLIST_REGEX = re.compile(
    '(sign|log|opt)[+-_]*(out|off)|leave',
    re.IGNORECASE
)

USER_AGENT = f'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1)' + \
    f'AppleWebKit/537.36 (KHTML, like Gecko)' + \
    f'Chrome/96.0.4664.11{random.randint(1, 9)} Safari/537.36'

BLACKLISTED_DOMAINS = [
    'doubleclick.net', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com',
    'googletagservices.com', 'googleapis.com',
    'googlesyndication.com', 'analytics.ticktok.com',
    'gstatic.com',
]


# =============================================================================
# ============================== CORS functions ===============================
# =============================================================================


def generate_variations(origin):
    parsed = urlparse(origin)
    variations = {}

    # 1: HTTPS trusts HTTP
    variations['https_trusts_http'] = origin.replace('https://', 'http://')

    # 2: arbitrary subdomain
    if len(parsed.netloc.split('.')) > 2:
        domain = '.'.join(parsed.netloc.split('.')[1:])
    else:
        domain = parsed.netloc
    variations['arbitrary_subdomain'] = (f'{parsed.scheme}://{get_random_string(4, 4).lower()}.{domain}')

    # 3: arbitrary origin reflection
    variations['arbitrary_origin_reflection'] = (f'{parsed.scheme}://{get_random_string(7, 7).lower()}.com')

    # 4: 'null' value
    variations['null_value'] = ('null')

    # 5: prefix matching
    variations['prefix_matching'] = (origin + f'.{get_random_string(4, 4).lower()}.com')

    # 6: not escaping '.'
    variations['non_escaped_dot'] = 'a'.join(origin.split('.'))

    # 7: suffix matching
    variations['suffix_matching'] = (origin.split('//')[0] + f'//{get_random_string(4, 4).lower()}' + origin.replace(origin.split('//')[0] + '//', '').replace('www.', ''))

    # 8: end matching
    variations['end_matching'] = f'{parsed.scheme}://{get_random_string(4, 4).lower()}.com/{origin}'

    return variations


def check_origin(headers, origin, _log=True):
    """
    Return a tuple containing
    - True if the Origin is allowed, False otherwise and
    - the value of the Access-Control-Allow-Origin header
    """
    if 'access-control-allow-origin' in headers:
        header = headers['access-control-allow-origin']

        # What if the Origin does not match but it gives allow anyway?
        return header == origin or \
                header == '*'    or \
                header == 'null', header
    else:
        return False, ''


def test_url(url, headers):
    """
    Tests a URL for CORS misconfigurations
    """
    global statisitcs, network
    parsed = urlparse(url)
    origin = parsed.scheme + '://' + parsed.netloc
    if len(headers) == 0:
        headers = {
            'Origin': origin,
            'User-Agent': USER_AGENT,
        }

    # Check if the site is using CORS on the URL to test
    response = browser.get(url, headers=headers)
    if url not in network:
        network[url] = {}
    network[url]['original'] = {
        'Origin': origin,
        'request_headers':  dict(response.request.headers),
        'response_headers': dict(response.headers),
    }

    successful, header = check_origin(response.headers, origin)

    # If the site is using CORS and does not accept
    # everything as an Origin: test the variations
    if successful and header != '*':
        logger.info(f'Original: {bcolors.OKBLUE}{origin}{bcolors.ENDC} on {url}')
        statistics['cors'] = True

        # Generate the variations based on the allowed Origin
        variations = generate_variations(origin)
        count = 0
        for variation in variations:
            count += 1
            if len(variations_to_test) > 0 and count not in variations_to_test:
                continue

            _headers = headers.copy()
            _headers['Origin'] = variations[variation]

            response = browser.get(url, headers=_headers)
            if url not in network:
                network[url] = {}
            network[url][variation] = {
                'Origin': variations[variation],
                'response_headers': dict(response.headers),
                'request_headers':  dict(response.request.headers)
            }

            successful, header = check_origin(response.headers, variations[variation])

            if successful:
                logger.info(f'{bcolors.FAIL}{variation}{bcolors.ENDC} ({bcolors.OKBLUE}{variations[variation]}{bcolors.ENDC}): {url} vulnerable')

                statistics['vulnerable'] = True
                if url not in statistics['vulnerable_urls']:
                    statistics['vulnerable_urls'][url] = []
                if variation not in statistics['vulnerable_urls'][url]:
                    statistics['vulnerable_urls'][url].append(variation)

                if variation not in statistics['variations']:
                    statistics['variations'].append(variation)
            else:
                logger.info(f'{variation} ({bcolors.WARNING}{variations[variation]}{bcolors.ENDC}): {url} not vulnerable')

    elif header == '*':
        statistics['cors'] = True
        statistics['wildcard'] = True
        logger.info(f'Wildcard')
        if url not in network:
            network[url] = {}
        network[url]['wildcard'] = {
            'Origin': '*',
            'response_headers': dict(response.headers),
            'request_headers':  dict(response.request.headers)
        }

        if 'access-control-allow-credentials' in response.headers and \
            response.headers['access-control-allow-credentials'] == 'true':
            statistics['vulnerable']    = True
            statistics['credentials']   = True
            logger.info(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} allows wildcard with credentials')

        else:
            statistics['credentials'] = False
            logger.info(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} allows wildcard')
    else:
        logger.info(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} not using CORS')


# Login detection functions


def get_login_url(urls):
    """
    Return the login url from the list of urls (if present).
    """
    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
        logger.debug(f'{bcolors.OKGREEN}[+]{bcolors.ENDC} {url}')

        if '/signin' in cleaned_url or \
            '/login' in cleaned_url and \
            '/join'  in cleaned_url and  \
            not '/hc/' in cleaned_url: # Ignore Zendesk support pages
            logger.debug(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains /login or /signin')
            return url

    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

        if 'signin' in cleaned_url or \
            'login' in cleaned_url and \
            not '/hc/' in cleaned_url:
            logger.debug(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains login or signin')
            return url
    return ''

def is_login_page(url, html):
    """
    Return True if the current page is a login PAGE.
    """
    cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

    if 'login' in cleaned_url or \
        'signin' in cleaned_url:
        logger.debug(f'Is login page because contains {bcolors.OKGREEN}login/signin{bcolors.ENDC}')
        return True
    
    soup = BeautifulSoup(html, 'html.parser')
    password = soup.find('input', {'type' : 'password'})
    if password is not None:
        logger.debug(f'Is login page because contains {bcolors.OKGREEN}a type=password input field{bcolors.ENDC} {password}')
        return True
    logger.debug(f'Is not login page')
    return False

# =============================================================================
# ============================= Helper functions ==============================
# =============================================================================

def get_random_string(start=10, end=20):
    return ''.join(random.choice(string.ascii_letters + string.digits + '_') for _ in range(random.randint(start, end)))

def clean_url(url):
    """
    Cleans the url to remove any trailing newlines and spaces.
    """
    return url.strip().strip('\n')

def save_dictionaries(site, crawler):
    """
    Save the dictionaries to the files.
    """
    global statistics, urls_to_test, network, tested, queue, visited_urls

    logs = {
        'urls_to_test': urls_to_test,
        'tested':       tested,
        'queue':   crawler.queue,
        'visited': crawler.visited_urls
    }

    with open(f'logs/{site}-logs.json', 'w') as f:
        json.dump(logs, f, indent=4)
    with open(f'stats/{site}-stats.json', 'w') as f:
        json.dump(statistics, f, indent=4)

    with open(f'network/{site}-network.json', 'w') as f:
        json.dump(network, f)


def get_dictionaries(site, crawler):
    """
    Load the dictionaries from the files.
    """
    global statistics, urls_to_test, network, tested, queue, visited_urls

    try:
        if os.path.exists(f'logs/{site}-logs.json'):
            with open(f'logs/{site}-logs.json', 'r') as f:
                logs = json.load(f)
                urls_to_test    = logs['urls_to_test']
                tested          = logs['tested']

                queue = logs['queue']
                visited_urls = logs['visited']

                crawler.set_visited_urls(visited_urls)
                crawler.set_queue(queue)
    except Exception as e:
        logging.error(e)

    try:
        if os.path.exists(f'stats/{site}-stats.json'):
            with open(f'stats/{site}-stats.json', 'r') as f:
                statistics = json.load(f)

        if os.path.exists(f'{NETWORK}/{SITE}-network.json'):
            with open(f'{NETWORK}/{SITE}-network.json', 'r') as f:
                network = json.load(f)
    except Exception as e:
        pass


# =============================================================================
# =================================== MAIN ====================================
# =============================================================================

def main():
    global SITE, urls_to_test, statistics, variations_to_test

    parser = argparse.ArgumentParser(prog='cors.py', description='Tool to detect CORS misconfigurations as seen in the paper "Mind the CORS"')

    parser.add_argument('-t', '--target',      required=False,
                        help='Target website')

    parser.add_argument('-L', '--links',
                        help='File containing the login links')

    parser.add_argument('-u', '--url',
                        help='Do not crawl the website, just test the given URL(s)')

    parser.add_argument('-m', '--max',         default=MAX_DEFAULT,
                        help=f'Maximum number of URLs to crawl (Default: {MAX_DEFAULT})')

    parser.add_argument('-v', '--variations',
                        help=f'What variations to test for (Count from 1. e.g., "1-5" or "1,4")')

    parser.add_argument('-r', '--retest', action='store_true',
                        help='Test already tested URLs')

    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug mode')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.url:
        c = 0
        _urls_to_test = {}
        for url in args.url.split(','):
            if url not in list(_urls_to_test.values()):
                if 'https://' not in url and 'http://' not in url:
                    url = 'https://' + url

                if 'www.' not in url:
                    _urls_to_test[f'test{c}'] = url
                    _urls_to_test[f'www_test{c}'] = \
                        url.replace('https://', 'https://www.').replace('http://', 'http://www.')
                else:
                    _urls_to_test[f'test{c}'] = url.replace('www.', '')
                    _urls_to_test[f'www_test{c}'] = url
                c += 1
        if args.target:
            SITE = (
                args.target
                .strip()
                .lower()
                .replace('http://',  '')
                .replace('https://', '')
                .replace('www.',    '')
            )
        else:
            SITE = urlparse(_urls_to_test['test0']).netloc.replace('www.', '')
    else:
        if args.links:
            with open(args.links, 'r') as f:
                file_links = json.load(f)
                SITE = file_links['site']
        elif args.target is None:
            logger.info(f'Target website not specified')
            exit()
        else:
            SITE    = (
                args.target
                .strip()
                .lower()
                .replace('http://',  '')
                .replace('https://', '')
                .replace('www.', '')
            )

    
    # Create folder if they dont'exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('stats'):
        os.mkdir('stats')
    if not os.path.exists('network'):
        os.mkdir('network')

    statistics['site'] = SITE
    if args.variations:
        if ',' in args.variations:
            variations_to_test = [int(i) for i in args.variations.split(',')]
        elif '-' in args.variations:
            variations_to_test = range(
                int(args.variations.split('-')[0]),
                int(args.variations.split('-')[1]) + 1
            )
        else:
            variations_to_test = [int(args.variations)]
        logger.info(f'Only testing variation(s): {", ".join([str(i) for i in variations_to_test])}')

    try:
        # Create the crawler
        crawler = Crawler(SITE, max=int(args.max))

        # Get dictionaries from the files
        get_dictionaries(SITE, crawler)
        if args.url:
            for url_type in _urls_to_test:
                if _urls_to_test[url_type] not in list(urls_to_test.values()):
                    urls_to_test[url_type] = _urls_to_test[url_type]

        # If the links file is provided: retrieve the links
        if args.links:
            for url_type in file_links:
                if url_type != 'site' and \
                    url_type not in list(urls_to_test.values()):
                    urls_to_test[url_type] = file_links[url_type]

        # 1. Find the homepage
        homepage_response = ''
        if 'homepage' not in urls_to_test and not args.url:
            logger.info(f'Crawling the site to collect the URLs to test')

            # Visit the homepage and follow redirects
            if 'homepage' not in urls_to_test:
                logger.info('Searching for the homepage')

                homepage_response = browser.get(f'http://{SITE}/', timeout=30)
                url = homepage_response.url
                crawler.add_to_visited(url)

                homepage = url
                print(f'found: {homepage}')

            elif 'homepage' in urls_to_test:
                homepage = urls_to_test['homepage']

            urls_to_test['homepage'] = homepage

        # 2. Find the in the homepage login page
        if 'login' not in urls_to_test and \
                'homepage' in urls_to_test and \
                args.url is None:
            logger.info('Searching for the login page')

            # Get links from the homepage
            if homepage_response != '':
                links = crawler.get_links(urls_to_test['homepage'], homepage_response.text, only_internal=True)

                login_url = get_login_url(links)
                if login_url != '':
                    urls_to_test['login'] = login_url
                    print(f'Found login page: {login_url}')
                for _url in links:
                    crawler.add_to_queue(_url)

        # 3. If login page not found in point 2: crawl the site
        while 'login' not in urls_to_test and crawler.should_continue() and args.url is None:
            url = crawler.get_url_from_queue()

            if LOGOUT_BLACKLIST_REGEX.search(url):
                continue

            response = browser.get(url)
            crawler.add_to_visited(url)

            # Get links from the page
            urls = crawler.get_links(response.url, response.text, only_internal=True)

            login_url = get_login_url(urls)
            if login_url != '':
                urls_to_test['login'] = login_url

            for _url in urls:
                crawler.add_to_queue(_url)

            # Check if it's the login page
            if 'login' not in urls_to_test and is_login_page(response.url, response.text):
                urls_to_test['login'] = url
                print(f'Found login page: {url}')
                break

        if not 'login' in urls_to_test and args.url is None:
            print('Login page not found')

        logger.info(f'Website crawled:\n{json.dumps(urls_to_test, indent=4)}')

        # Test the URLs for CORS misconfigurations
        _tested = [] # Needed when retest is used
        for url_type in urls_to_test:
            url = urls_to_test[url_type]
            if not url.startswith('http'):
                continue

            if not args.retest and crawler.get_template_url(url) in tested:
                continue
            elif args.retest and crawler.get_template_url(url) in _tested:
                continue

            try:
                test_url(url, headers_to_test[url] if url in headers_to_test else {})
                tested.append(crawler.get_template_url(url))
                _tested.append(crawler.get_template_url(url))
            except (NewConnectionError, MaxRetryError, ConnectionError):
                logger.error(f'Cannot test {url}')
                pass
            except:
                logger.error(f'Error testing {url}')
                traceback.print_exc()

    except SystemExit as e:
        save_dictionaries(SITE, crawler=crawler)
        sys.exit(e)
    except (SSLError, NewConnectionError, MaxRetryError,
            ConnectionError, ReadTimeoutError, ReadTimeout):
        save_dictionaries(SITE, crawler=crawler)
        logger.error(f'{SITE} timed out')
        sys.exit(1)
    except KeyboardInterrupt:
        save_dictionaries(SITE, crawler=crawler)
        exit(0)
    except:
        save_dictionaries(SITE, crawler=crawler)
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        save_dictionaries(SITE, crawler=crawler)
        logger.info(f'All done!')
        sys.exit(0)

if __name__ == '__main__':
    main()
