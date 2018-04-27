# Security Trails Python API
import requests
import logging
import json

# Establish Logging.
logging.basicConfig()
logger = logging.getLogger('securitytrails')


class securitytrails():
    def __init__(
        self,
        api_key,
        base_url='https://api.securitytrails.com/v1/',
        prettyPrint=False
    ):
        """
        SecurityTrails Python Wrapper.  Implementation of production release from https://jsapi.apiary.io/apis/securitytrailsrestapi/introduction/authentication.html

        Available Functions
        - test_connect              Provides a method to test connectivity
        - get_domain                Domain information endpoints that return various information about domains.
        - get_subdomain             Returns subdomains for a given domain.
        - get_tags                  Returns tags for a given domain.
        - get_whois                 Returns the current WHOIS data about a given domain with the stats merged together.
        - get_history_dns           Lists out specific historical information about the given domain parameter.
        - get_history_whois         Returns the current WHOIS data about a given domain with the stats merged together.
        - ip_explorer               Returns the neighbors in any given IP level range and essentially allows you to explore closeby IP addresses.
        - domain_searcher           Filter and search specific records using this endpoint. Using simple filter composition, any type of data fetching is possible.
                                    The post object uses a very simple dsl where the json key represents the type to filter on and the value.
                                    Given this, you can create any number of queries, depending on the need.
                                    It's worth noting that all of the filters are combined using AND fashion and work in combination.
        - domain_searcher_stats     By appending /stats at the end of the search URL, instead of getting the usual records, a stats object is given in the response.
                                    This object contains some usefull information like:tld count, hostname count, domain count

        Usage:
        s = securitytrails(api_key='yourapikey')

        s.function_name(valid_variables)
        """

        # Create Requests Session
        self.session = requests.session()
        # Add API Key to Header
        self.session.headers.update({'APIKEY': api_key})
        # Create Base URL variable to allow for updates in the future
        self.base_url = base_url
        # Create API Key variable to pass into each request
        self.api_key = api_key
        # Create Pretty Print variable
        self.prettyPrint = prettyPrint

        # Check to see if API Key is present
        if self.api_key is None:
            raise Exception("No API Key present")

        # Initiate Ping to Security Trails
        self.ping = self.session.get(base_url + "ping")

        # Request failed returning false and logging an error
        if self.ping.status_code != 200:
            logger.error(
                "Error connecting to Security Trails, error message: {}".format(
                    self.ping.text))

    def parse_output(self, input):
        # If prettyPrint set to False
        if self.prettyPrint == False:
            return json.dumps(input)
        # If prettyPrint set to True
        elif self.prettyPrint == True:
            print json.dumps(input, indent=4)

    def test_connect(self):
        """
        Function:   Test ping to Security Trails API

        No parameters: Relies on API key being set.  Returns True for successful connection and False for unsuccessful.

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.test_connect()
        """

        endpoint = '{}/ping/'.format(self.base_url)
        # Make connection to the ping endpoint
        r = self.session.get(endpoint)
        # Specify Output as JSON
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return True
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_domain:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def get_domain(self, domain):
        """
        Function:   Domain information endpoints that return various information about domains.

        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_domain("netflix.com")
        """

        endpoint = '{}/domain/{}'.format(self.base_url, domain)
        r = self.session.get(endpoint)
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_domain:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def get_subdomain(self, domain):
        """
        Function:   Returns subdomains for a given domain.

        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_subdomain("netflix.com")
        """

        endpoint = '{}/domain/{}/subdomains'.format(self.base_url, domain)
        # Make connection to the subdomain endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_subdomain:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def get_tags(self, domain):
        """
        Function:   Returns tags for a given domain.

        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_tags("netflix.com")
        """
        endpoint = '{}/domain/{}/tags'.format(self.base_url, domain)
        # Make connection to the tags endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_tags:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def get_whois(self, domain):
        """
        Function:   Returns the current WHOIS data about a given domain with the stats merged together.

        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_whois("netflix.com")
        """
        endpoint = '{}/domain/{}/whois'.format(self.base_url, domain)
        # Make connection to the whois endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_whois:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def get_history_dns(self, domain, record_type):
        """
        Function:   Lists out specific historical information about the given domain parameter.

        :param domain: Required - The domain that you are requesting
        :param record_type: Required - Valid types a, aaaa, mx, ns, txt, soa

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_dns("netflix.com", "a",)

        s = securitytrails(api_key='yourapikey')
        s.get_history_dns("netflix.com", "mx")
        """

        # Convert the record_type to lower case
        record_type = record_type.lower()

        # Validate record_type type variable
        type_check = ['a', 'aaaa', 'mx', 'ns', 'txt', 'soa']

        if record_type in type_check:
            # Returns the history dns data about a given domain with the stats
            # merged together.
            endpoint = '{}/history/{}/dns/{}'.format(
                self.base_url, domain, record_type)
            # Make connection to the history dns endpoint
            r = self.session.get(endpoint)
            # If the request is successful
            if r.status_code == 200:
                # Output results to json
                return self.parse_output(r.json())
            else:
                # Request failed returning false and logging an error
                # Output results to json
                output = r.json()
                logger.warning(
                    "get_history_dns:Error with query to Security Trails, error message: {}".format(
                        output['message']))
                return False

        # Request failed returning false and logging an error
        else:
            logger.warning("get_history_dns: Invalid type, valid types are {}.".format(
                str(", ".join(type_check))))
            return False

    def get_history_whois(self, domain):
        """
        Function:   Returns the current WHOIS data about a given domain with the stats merged together.

        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_whois("netflix.com")

        """
        endpoint = '{}/history/{}/whois'.format(self.base_url, domain)
        r = self.session.get(endpoint)
        # If the request is successful
        if r.status_code == 200:
            # Output results to json
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            # Output results to json
            output = r.json()
            logger.warning(
                "get_history_whois:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def ip_explorer(self, ip, mask=32):
        """
        Function:   Returns the neighbors in any given IP level range and essentially allows you to explore closeby IP addresses.

        :param ip: Required - The domain that you are requesting
        :param mask Required - Defaults to 32 bit mask

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.ip_explorer("netflix.com")

        """
        endpoint = '{}/explore/ip/{}'.format(self.base_url, ip)
        r = self.session.get(endpoint)
        # If the request is successful
        if r.status_code == 200:
            # Output results to json
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            # Output results to json
            output = r.json()
            logger.warning(
                "ip_explorer:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def domain_searcher(self, **kwargs):
        """
        Function:       Filter and search specific records using this endpoint. Using simple filter composition, any type of data fetching is possible.
                        The post object uses a very simple dsl where the json key represents the type to filter on and the value.
                        Given this, you can create any number of queries, depending on the need.
                        It's worth noting that all of the filters are combined using AND fashion and work in combination.

        :param
                        ipv4                IPv4 Address
                        ipv6                IPv6 Address
                        mx                  MX Address
                        ns                  DNS Name Server
                        cname               DNS CNAME
                        subdomain           Subdomain of host
                        apex_domain         In dev.securitytrails.securitytails.com would be securitytails.com
                        soa_email           Start of Authority Email Address
                        tld                 Top Level Domain
                        whois_email         Registered Whois Email
                        whois_street1       Registered Whois Street 1
                        whois_street2       Registered Whois Street 2
                        whois_street3       Registered Whois Street 3
                        whois_street4       Registered Whois Street 4
                        whois_telephone     Registered Whois Telephone
                        whois_postalCode    Registered Whois Postal Code
                        whois_organization  Registered Whois Organization
                        whois_name          Registered Whois Name
                        whois_fax           Registered Whois Fax
                        whois_city          Registered Whois City
                        keyword             Keyword Filter

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx="alt4.aspmx.l.google.com",keyword: "stackover")

        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx="alt4.aspmx.l.google.com",keyword: "stackover")

        """
        endpoint = '{}/search/list'.format(self.base_url)
        self.session.headers.update(
            {'Content-Type': 'application/json', 'APIKEY': self.api_key})

        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = [
            "ipv4",
            "ipv6",
            "mx",
            "ns",
            "cname",
            "subdomain",
            "apex_domain",
            "soa_email",
            "tld",
            "whois_email",
            "whois_street1",
            "whois_street2",
            "whois_street3",
            "whois_street4",
            "whois_telephone",
            "whois_postalCode",
            "whois_organization",
            "whois_name",
            "whois_fax",
            "whois_city",
            "keyword"]

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning(
                    "domain_searcher:Error with query to Security Trails.  {} is not a valid filter. Ignoring this key.  Valid formats are: {}".format(
                        str(key), str(
                            ", ".join(valid_filter))))

            else:
                values['filter'][key] = value

        if values['filter']:
            r = self.session.post(endpoint, data=json.dumps(values))
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "domain_searcher:Error with query to Security Trails. No valid keys added to search.")
            return False

        # If the request is successful
        if r.status_code == 200:
            # Output results to json
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            # Output results to json
            output = r.json()
            logger.warning(
                "domain_searcher:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False

    def domain_searcher_stats(self, **kwargs):
        """
        Function:       By appending /stats at the end of the search URL, instead of getting the usual records, a stats object is given in the response.
                        This object contains some usefull information like:tld count, hostname count, domain count

        :param
                        ipv4                IPv4 Address
                        ipv6                IPv6 Address
                        mx                  MX Address
                        ns                  DNS Name Server
                        cname               DNS CNAME
                        subdomain           Subdomain of host
                        apex_domain         In dev.securitytrails.securitytails.com would be securitytails.com
                        soa_email           Start of Authority Email Address
                        tld                 Top Level Domain
                        whois_email         Registered Whois Email
                        whois_street1       Registered Whois Street 1
                        whois_street2       Registered Whois Street 2
                        whois_street3       Registered Whois Street 3
                        whois_street4       Registered Whois Street 4
                        whois_telephone     Registered Whois Telephone
                        whois_postalCode    Registered Whois Postal Code
                        whois_organization  Registered Whois Organization
                        whois_name          Registered Whois Name
                        whois_fax           Registered Whois Fax
                        whois_city          Registered Whois City
                        keyword             Keyword Filter

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx="alt4.aspmx.l.google.com",keywords="stackover"))

        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(whois_postalCode=94016,keyword="services")

        """
        # By appending /stats at the end of the search URL, instead of getting
        # the usual records, a stats object is given in the response. This
        # object contains some usefull information like:tld count, hostname
        # count, domain count
        endpoint = '{}/search/list/stats'.format(self.base_url)
        self.session.headers.update(
            {'Content-Type': 'application/json', 'APIKEY': self.api_key})

        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = [
            "ipv4",
            "ipv6",
            "mx",
            "ns",
            "cname",
            "subdomain",
            "apex_domain",
            "soa_email",
            "tld",
            "whois_email",
            "whois_street1",
            "whois_street2",
            "whois_street3",
            "whois_street4",
            "whois_telephone",
            "whois_postalCode",
            "whois_organization",
            "whois_name",
            "whois_fax",
            "whois_city",
            "keyword"]

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning(
                    "domain_searcher_stats:Error with query to Security Trails.  {} is not a valid filter. Ignoring this key.  Valid formats are: {}".format(
                        str(key), str(
                            ", ".join(valid_filter))))

            else:
                values['filter'][key] = value

        if values['filter']:
            r = self.session.post(endpoint, data=json.dumps(values))

        else:
            logger.warning(
                "domain_searcher_stats:Error with query to Security Trails. No valid keys added to search.")
            return False

        # If the request is successful
        if r.status_code == 200:
            # Output results to json
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            # Output results to json
            output = r.json()
            logger.warning(
                "domain_searcher_stats:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False
