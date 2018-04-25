#Security Trails Python API
import requests
import logging
import json

#Establish Logging.
logging.basicConfig()
logger = logging.getLogger('securitytrails')


class securitytrails():
    def __init__(
        self,
        api_key,
        base_url='https://api.securitytrails.com/v1/'
        ):

        # Create Requests Session
        self.session = requests.session()
        # Add API Key to Header
        self.session.headers.update({'APIKEY': api_key})
        # Create Base URL variable to allow for updates in the future
        self.base_url = base_url
        # Create API Key variable to pass into each request
        self.api_key = api_key   

        # Check to see if API Key is present
        if self.api_key is None:
            raise Exception("No API Key present")

        # Initiate Ping to Security Trails
        self.ping = self.session.get(base_url+"ping")
        
        # Test connection to website
        # If the request fails
        if self.ping.status_code != 200:
            logger.warning("Error connecting to Security Trails, error message: {}".format(self.ping.text))

    def test_connect(self):
        # Test ping to Security Trails API
        endpoint = '{}/ping/'.format(self.base_url)
        # Make connection to the ping endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request fails
        if r.status_code != 200:
            logger.warning("get_domain:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            return True


    def get_domain(self,domain):
        # Domain information endpoints that return various information about domains.
        endpoint = '{}/domain/{}'.format(self.base_url,domain)
        r = self.session.get(endpoint)
        output = r.json()
        # If the request fails
        if r.status_code != 200:
            logger.warning("get_domain:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            return output
    
    def get_subdomain(self,domain):
        # Returns subdomains for a given domain.
        endpoint = '{}/domain/{}/subdomains'.format(self.base_url,domain)
        # Make connection to the subdomain endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request fails
        if r.status_code != 200:
            logger.warning("get_subdomain:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            return output

    
    def get_tags(self,domain):
        # Returns tags for a given domain.
        endpoint = '{}/domain/{}/tags'.format(self.base_url,domain)
        # Make connection to the tags endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request fails
        if r.status_code != 200:
            logger.warning("get_tags:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            return output

    def get_whois(self,domain):
        # Returns the current WHOIS data about a given domain with the stats merged together.
        endpoint = '{}/domain/{}/whois'.format(self.base_url,domain)
        # Make connection to the whois endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request fails
        if r.status_code != 200:
            logger.warning("get_whois:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            return output

    def get_history_dns(self,domain,record_type):
        """
        :param domain: Required - The domain that you are requesting
        :param record_type: Required - Valid types a, aaaa, mx, ns, txt, soa

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_dns("netflix.com", "a",)

        s = securitytrails(api_key='yourapikey')
        s.get_history_dns("netflix.com", "mx")
        """
        # Lists out specific historical information about the given domain parameter.

        # Convert the record_type to lower case
        record_type = record_type.lower()
        
        # Validate record_type type variable
        type_check = ['a', 'aaaa','mx','ns','txt','soa']

        if record_type in type_check:
            # Returns the history dns data about a given domain with the stats merged together.
            endpoint = '{}/history/{}/dns/{}'.format(self.base_url,domain,record_type)
            # Make connection to the history dns endpoint
            r = self.session.get(endpoint)
            # If the request fails
            if r.status_code != 200:
                # Output results to json
                output = r.json()
                logger.warning("get_history_dns:Error with query to Security Trails, error message: {}".format(output['message']))
                return False
            else:
                # Output results to json
                output = r.json()
                return output
        
        else:
            logger.warning("get_history_dns: Invalid type, valid types are {}.  Error message received from server: {}".format(str(", ".join(type_check)),output['message']))
            return False

    def get_history_whois(self,domain):
        """
        :param domain: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.get_history_whois("netflix.com")

        """
        # Returns the current WHOIS data about a given domain with the stats merged together.
        endpoint = '{}/history/{}/whois'.format(self.base_url,domain)
        r = self.session.get(endpoint)
        # If the request fails
        if r.status_code != 200:
            # Output results to json
            output = r.json()
            logger.warning("get_history_whois:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            # Output results to json
            output = r.json()
            return output

    def ip_explorer(self,ip,mask=32):
        """
        :param ip: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.ip_explorer("netflix.com")

        """
        # Returns the neighbors in any given IP level range and essentially allows you to explore closeby IP addresses. This works by providing a specific IP address (or by starting at the whole unzoomed level). Explorer will always yield IPs that will be grouped in blocks, so the output will always be 16.
        endpoint = '{}/explore/ip/{}'.format(self.base_url,ip)
        r = self.session.get(endpoint)
        # If the request fails
        if r.status_code != 200:
            # Output results to json
            output = r.json()
            logger.warning("ip_explorer:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            # Output results to json
            output = r.json()
            return output

    def domain_searcher(self, **kwargs):
        """
        :param ip: Required - The domain that you are requesting

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher("netflix.com")

        """
        # Filter and search specific records using this endpoint. Using simple filter composition, any type of data fetching is possible. The post object uses a very simple dsl where the json key represents the type to filter on and the value. Given this, you can create any number of queries, depending on the need. It's worth noting that all of the filters are combined using AND fashion and work in combination.
        endpoint = '{}/search/list'.format(self.base_url)
        self.session.headers.update({'Content-Type': 'application/json','APIKEY': self.api_key})
        
        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = ["ipv4", "ipv6", "mx", "ns", "cname", "subdomain", "apex_domain", "soa_email", "tld", "whois_email", "whois_street1", "whois_street2", "whois_street3", "whois_street4", "whois_telephone", "whois_postalCode", "whois_organization", "whois_name", "whois_fax", "whois_city", "keyword"]

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning("domain_searcher:Error with query to Security Trails.  {} is not a valid filter. Ignoring this key.  Valid formats are: {}".format(str(key), str(", ".join(valid_filter))))

            else:
                values['filter'][key] = value
        
        if values['filter']:
            r = self.session.post(endpoint,data=json.dumps(values))

        else:
            logger.warning("domain_searcher:Error with query to Security Trails. No valid keys added to search.")
            return False

        # If the request fails
        if r.status_code != 200:
            # Output results to json
            output = r.json()
            logger.warning("domain_searcher:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            # Output results to json
            output = r.json()
            return output


    def domain_searcher_stats(self, **kwargs):
        """
        :param List : Required - The type of information you want to filter on
        ipv4, ipv6, mx, ns, cname, subdomain, apex_domain, soa_email, tld, whois_email, whois_street1, whois_street2, whois_street3, whois_street4, whois_telephone, whois_postalCode, whois_organization, whois_name, whois_fax, whois_city, keyword

        Usage:
        s = securitytrails(api_key='yourapikey')
        s.domain_searcher(mx="alt4.aspmx.l.google.com",keywords="stackover"))

        """
        # By appending /stats at the end of the search URL, instead of getting the usual records, a stats object is given in the response. This object contains some usefull information like:tld count, hostname count, domain count
        endpoint = '{}/search/list/stats'.format(self.base_url)
        self.session.headers.update({'Content-Type': 'application/json','APIKEY': self.api_key})
        
        # Establish empty filter dictionary object with a filter list.
        values = {}
        values['filter'] = {}

        # Array of valid keywords
        valid_filter = ["ipv4", "ipv6", "mx", "ns", "cname", "subdomain", "apex_domain", "soa_email", "tld", "whois_email", "whois_street1", "whois_street2", "whois_street3", "whois_street4", "whois_telephone", "whois_postalCode", "whois_organization", "whois_name", "whois_fax", "whois_city", "keyword"]

        for key, value in kwargs.iteritems():
            if key not in valid_filter:
                logger.warning("domain_searcher_stats:Error with query to Security Trails.  {} is not a valid filter. Ignoring this key.  Valid formats are: {}".format(str(key), str(", ".join(valid_filter))))

            else:
                values['filter'][key] = value
        
        if values['filter']:
            r = self.session.post(endpoint,data=json.dumps(values))

        else:
            logger.warning("domain_searcher_stats:Error with query to Security Trails. No valid keys added to search.")
            return False

        # If the request fails
        if r.status_code != 200:
            # Output results to json
            output = r.json()
            logger.warning("domain_searcher_stats:Error with query to Security Trails, error message: {}".format(output['message']))
            return False
        else:
            # Output results to json
            output = r.json()
            return output