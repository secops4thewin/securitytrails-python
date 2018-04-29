# securitytrails-python
Provides a python wrapper to the security trails api.

##### SecurityTrails
**Usage**

| Parameter | Details | Required |
| --- | --- | --- |
| domain | The domain that you are requesting | Required |

**Example**

   ` s = SecurityTrails(api_key='yourapikey') `
   ` s.get_history_whois("netflix.com") `

##### get_subdomain
**Function**
Returns subdomains for a given domain.

**Usage**

 | Parameter | Details | Required |
---         |  ---       |    ---
domain      | The domain that you are requesting    |   Required
**Example**
 
```s = SecurityTrails(api_key='yourapikey')```
```s.get_subdomain("netflix.com")```
##### get_tags
**Function**
Returns tags for a given domain.

**Usage**
 Parameter   | Details    | Required
---         |  ---       |    ---
domain      | The domain that you are requesting    |   Required
**Example**

```s = SecurityTrails(api_key='yourapikey')```
```s.get_tags("netflix.com")```

##### get_whois
**Function**
Returns the current WHOIS data about a given domain with the stats merged together.

**Usage**
 Parameter   | Details    | Required
---         |  ---       |    ---
domain      | The domain that you are requesting    |   Required
**Example**
```s = SecurityTrails(api_key='yourapikey')```
```s.get_whois("netflix.com")```

##### ip_explorer
**Function**
Returns the neighbors in any given IP level range and essentially allows you to explore closeby IP addresses.
**Usage**
 Parameter   | Details    | Required
---         |  ---       |    ---
ip      | The ip that you are requesting    |   Required
mask    | The IP mask. Defaults to 32 bit mask | Required
**Example**
  
```s = SecurityTrails(api_key='yourapikey')```
```s.ip_explorer("netflix.com")```

##### test_connect
**Function**
Test ping to Security Trails API

**No parameters**: 
Relies on API key being set.  Returns True for successful connection and False for unsuccessful.

**Usage**
 ```s = SecurityTrails(api_key='yourapikey')```
```s.test_connect()```