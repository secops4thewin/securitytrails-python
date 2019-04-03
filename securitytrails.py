#!/usr/bin/env python3
##
# Security Trails API wrapper for Python 3.7
# API documentation from https://docs.securitytrails.com/docs/overview
# --
# https://github.com./deadbits/securitytrails-python3
##
import json
import logging
import datetime
import requests
import validators

from pygments import lexers
from pygments import highlight
from pygments import formatters

# Establish Logging.
logging.basicConfig()
logger = logging.getLogger('securitytrails')

# make dates nice for JSON
# @todo: make this into a class instead of lambda
jsondate = lambda obj: obj.isoformat() if isinstance(obj, datetime) else None


class SecurityTrails:
    """
    Available Functions
    - test_connect              Test connectivity
    - get_domain                Get various information about domains
    - get_subdomain             Get subdomains for a given domain
    - get_tags                  Get tags for a given domain
    - get_whois                 Get current WHOIS data for a given domain with the stats merged
    - get_history_dns           Get specific historical DNS information for a given domain
    - get_history_whois         Get specific historical WHOIS information for agiven domain.
    - ip_explorer               Get the neighbors of a given IP address range
    - domain_searcher           Filter and search specific records using this endpoint. Using simple filter composition, any type of data fetching is possible.
                                The post object uses a very simple dsl where the json key represents the type to filter on and the value.
                                Given this, you can create any number of queries, depending on the need.
                                It's worth noting that all of the filters are combined using AND fashion and work in combination.
    - domain_searcher_stats     By appending /stats at the end of the search URL, instead of getting the usual records, a stats object is given in the response.
                                This object contains some usefull information like:tld count, hostname count, domain count
    """
    def __init__(self, api_key, pretty_print=False):
        """ SecurityTrails API wrapper

        @param api_key: securitytrails API key
        @type api_key: string

        @param pretty_print: specify if you want to return raw JSON or pretty print it
        @type pretty_print: bool

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.function_name(valid_variables)
        """
        self.api_key = api_key
        if not isinstance(self.api_key, str) and self.api_key == '':
            raise Exception('Invalid API key provided')

        self.base_url = 'https://api.securitytrails.com/v1/'

        # if users try to set their own base API URL, lets make sure they are actual URLs
        if not validators.url(self.base_url):
            raise ValueError(f'[main] self.base_url of {self.base_url} is not a valid URL')

        self._session = requests.Session()
        self._session.headers.update({'Content-Type': 'application/json', 'APIKEY': self.api_key})

        self.pretty_print = pretty_print

        ping_test = self.test_connect()
        if ping_test:
            logger.debug('[main] successfully tested ping to API')
        else:
            logger.error('[main] error connecting to API')

    def _parse_output(self, input):
        """ Parse JSON output from API response

        @param input: API response data
        @type dict

        @return: API response data as JSON
        @rtype: str
        """
        if self.pretty_print is False:
            return json.dumps(input)

        elif self.pretty_print:
            print(
                highlight(
                    json.dumps(
                        input,
                        indent=4,
                        default=jsondate
                    ),
                    lexers.JsonLexer(),
                    formatters.TerminalFormatter()
                )
            )

    def test_connect(self):
        """ Test ping to SecurityTrails API

        @return: True if successful connection or False for unsuccesful
        @rtype: bool

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.test_connect()
        """
        try:
            req = self._session.get(f'{self.base_url}/ping/')
        except Exception as err:
            raise Exception(f'Failed to ping API: {err}')

        output = req.json()

        if req.ok:
            return True

        else:
            logger.error(f'[test_connect] failed to ping API. error: {output["message"]}')
            return False

    def get_domain(self, domain):
        """Get information on specified domain name

        @param domain: domain name
        @type: str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_domain('netflix.com')
        """
        try:
            req = self._session.get(f'{self.base_url}/domain/{domain}')
        except Exception as err:
            raise Exception(f'Failed to make GET request: {err}')

        output = req.json()

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[get_domain] failed to query API. error: {output["message"]}')
            return False

    def get_subdomain(self, domain):
        """Get subdomains for specified domain name

        @param domain: domain name
        @type: str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_subdomain('netflix.com')
        """
        try:
            req = self._session.get(f'{self.base_url}/domain/{domain}/subdomains')
        except Exception as err:
            raise Exception(f'Failed to make GET request: {err}')

        output = req.json()

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[get_subdomain] failed to query API. error: {output["message"]}')
            return False

    def get_tags(self, domain):
        """Get tags for specified domain name

        @param domain: domain name
        @type: str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_tags('netflix.com')
        """
        try:
            req = self._session.get(f'{self.base_url}/domain/{domain}/tags')
        except Exception as err:
            raise Exception(f'Failed to make GET request: {err}')

        output = req.json()

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[get_tag] failed to query API. error: {output["message"]}')
            return False

    def get_whois(self, domain):
        """Get current WHOIS data on specified domain with the stats merged

        @param domain: domain name
        @type: str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_whois('netflix.com')
        """
        try:
            req = self._session.get(f'{self.base_url}/domain/{domain}/whois')
        except Exception as err:
            raise Exception(f'Failed to make GET request: {err}')

        output = req.json()

        if req.ok:
            return self._parse_output(req.json())

        logger.error(f'[get_whois] failed to query API. error: {output["message"]}')
        return False

    def get_history_dns(self, domain, record_type):
        """ Get specific historical WHOIS information for agiven domain

        @param domain: Required - The domain that you are requesting
        @type: str

        @param record_type: DNS record type (accepted: A, AAAA, MX, NX, TXT, SOA)
        @type: str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_dns('netflix.com', 'a',)

        s = securitytrails(api_key='yourapikey')
        s.get_history_dns('netflix.com', 'mx')
        """
        record_type = record_type.lower()
        type_check = ['a', 'aaaa', 'mx', 'ns', 'txt', 'soa']

        if record_type in type_check:
            try:
                req = self._session.get(f'{self.base_url}/history/{domain}/dns/{record_type}')
            except Exception as err:
                raise Exception(f'[get_history_dns] failed to make GET request: {err}')

            if req.ok:
                return self._parse_output(req.json())

            logger.error(f'[get_history_dns] failed to query API. error: {req.json()["message"]}')
            return False

        else:
            logger.error(f'[get_history_dns] invalid DNS record type. accepted {str(", ".join(type_check))}')
            return False

    def get_history_whois(self, domain):
        """Get current WHOIS data for given domain with stats merged

        @param domain: domain name
        @type str

        @return: API response data as JSON
        @rtype: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_whois('netflix.com')
        """
        try:
            req = self._session.get(f'{self.base_url}/history/{domain}/whois')
        except Exception as err:
            raise Exception(f'[get_history_whois] failed to make GET request: {err}')

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[get_history_whois] failed to query API. error: {req.json()["message"]}')
            return False

    def ip_explorer(self, ip, mask=32):
        """ Get the IP neighbors of a given domain by IP address range

        @param ip: IP address
        @type: str

        @param mask: IP bit mask
        @type int

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.ip_explorer('netflix.com', mask=32)

        """
        try:
            req = self._session.get(f'{self.base_url}/explore/ip/{ip}')
        except Exception as err:
            raise Exception(f'[ip_explorer] failed to make GET request: {err}')

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[ip_explorer] failed to query API. error message: {req.json()["message"]}')
            return False

    def domain_searcher(self, **kwargs):
        """ Get specific records of domains using keyword filters

        @note: Filter and search specific records using this endpoint.
        @note: It is possible to fetch any type  of data using simple filter composition.
        @note: The post object uses a very simple DSL where the JSON key represents the type to filter on and the value.
        @note: All of the filters can be combined using 'AND' to work in combination, allowing you to create any number of queries.

        @param ipv4:    ipv4 address
        @type: str

        @param ipv6:    ipv6 address
        @type: str

        @param mx:      MX address
        @type: str

        @param ns:      DNS name server
        @type: str

        @param cname:   DNS CNAME
        @type: str

        @param apex_domain: root domain of host
        @type: str

        @param subdomain: subdomain of host
        @type: str

        @param soa_email: SOA email address
        @type: str

        @param tld:     top level domain
        @type: str

        @param whois_email: WHOIS email address
        @type: str

        @param whois_street1: WHOIS street line 1
        @type: str

        @param whois_street2: WHOIS street line 2
        @type: str

        @param whois_street3: WHOIS street line 3
        @type: str

        @param whois_street4: WHOIS street line 5
        @type: str

        @param whois_telephone: WHOIS telephone number
        @type: str

        @param whois_postalCode: WHOIS postal code
        @type: str

        @param whois_organization: WHOIS organization
        @type: str

        @param whois_name: WHOIS name
        @type: str

        @param whois_fax: WHOIS fax number
        @type: str

        @param whois_city: WHOIS city
        @type: str

        @param keyword: keyword filter
        @type: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx='alt4.aspmx.l.google.com',keyword: 'stackover')

        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx='alt4.aspmx.l.google.com',keyword: 'stackover')
        """
        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = [
            'ipv4',
            'ipv6',
            'mx',
            'ns',
            'cname',
            'subdomain',
            'apex_domain',
            'soa_email',
            'tld',
            'whois_email',
            'whois_street1',
            'whois_street2',
            'whois_street3',
            'whois_street4',
            'whois_telephone',
            'whois_postalCode',
            'whois_organization',
            'whois_name',
            'whois_fax',
            'whois_city',
            'keyword']

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning(f'[domain_searcher] {str(key)} is not a valid filter; ignoring this key')
                logger.warning(f'[domain_searcher] valied formats are: {str(", ".join(valid_filter))}')
            else:
                values['filter'][key] = value

        if values['filter']:
            try:
                req = self._session.post(
                    f'{self.base_url}/search/list',
                    data=json.dumps(values)
                )
            except Exception as err:
                raise Exception(f'Failed to make GET request: {err}')

        else:
            logger.error('[domain_searcher] failed to query API. error: no valid keys in search')
            return False

        # If the request is successful
        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[domain_searcher] failed to query API. error: {req.json()["message"]}')
            return False

    def domain_searcher_stats(self, **kwargs):
        """Get statistics of a host containing data such as tld, hostname, and domain count

        @param ipv4:    ipv4 address
        @type: str

        @param ipv6:    ipv6 address
        @type: str

        @param mx:      MX address
        @type: str

        @param ns:      DNS name server
        @type: str

        @param cname:   DNS CNAME
        @type: str

        @param apex_domain: root domain of host
        @type: str

        @param subdomain: subdomain of host
        @type: str

        @param soa_email: SOA email address
        @type: str

        @param tld:     top level domain
        @type: str

        @param whois_email: WHOIS email address
        @type: str

        @param whois_street1: WHOIS street line 1
        @type: str

        @param whois_street2: WHOIS street line 2
        @type: str

        @param whois_street3: WHOIS street line 3
        @type: str

        @param whois_street4: WHOIS street line 5
        @type: str

        @param whois_telephone: WHOIS telephone number
        @type: str

        @param whois_postalCode: WHOIS postal code
        @type: str

        @param whois_organization: WHOIS organization
        @type: str

        @param whois_name: WHOIS name
        @type: str

        @param whois_fax: WHOIS fax number
        @type: str

        @param whois_city: WHOIS city
        @type: str

        @param keyword: keyword filter
        @type: str

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx='alt4.aspmx.l.google.com',keywords='stackover'))

        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(whois_postalCode=94016,keyword='services')

        """
        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = [
            'ipv4',
            'ipv6',
            'mx',
            'ns',
            'cname',
            'subdomain',
            'apex_domain',
            'soa_email',
            'tld',
            'whois_email',
            'whois_street1',
            'whois_street2',
            'whois_street3',
            'whois_street4',
            'whois_telephone',
            'whois_postalCode',
            'whois_organization',
            'whois_name',
            'whois_fax',
            'whois_city',
            'keyword']

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning(f'[domain_searcher_stats] {str(key)} is not a valid filter; ignoring this key')
                logger.warning(f'valid formats are: {str(", ".join(valid_filter))}')

            else:
                values['filter'][key] = value

        if values['filter']:
            try:
                req = self._session.post(
                    f'{self.base_url}/search/list/stats',
                    data=json.dumps(values)
                )
            except Exception as err:
                raise Exception(f'[domain_searcher_stats] Failed to make GET request: {err}')

        else:
            logger.error('[domain_searcher_stats] failed to query API. error: no valid filters provided')
            return False

        if req.ok:
            return self._parse_output(req.json())

        else:
            logger.error(f'[domain_searcher_stats] failed to query API. error: {req.json()["message"]}')
            return False
