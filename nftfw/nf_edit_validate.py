""" Validate IPs, Ports and Patterns """

import ipaddress
import socket
import logging
log = logging.getLogger('nftfw')

def validate_and_return_ip(ipstr):
    """Validate an IP address

    Given an IP address from the user:
    Get it into a form that the system would
    use it in the database

    Remove .auto so it can be used with * in the blacklist directory

    Parameters
    ----------
    ipstr : str
        IP address

    Returns
    -------
    str
        Return canonical form of the string or None
    """

    if '.auto' in ipstr:
        ipstr = ipstr.replace('.auto', '')

    # see if the user has used the | form
    if '|' in ipstr:
        ipstr = ipstr.replace('|', '/')

    try:
        if '/' in ipstr:
            i = ipaddress.ip_network(ipstr, strict=False)
        else:
            i = ipaddress.ip_address(ipstr)
        return str(i)
    except ValueError as e:
        log.error('Problem with %s: %s', ipstr, str(e))
        return None

def validate_and_return_ip_list(iplist):
    """Validate a list of IP addresses

    Parameters
    ----------
    iplist : List[str]
        List of IP addresses

    Returns
    -------
    List
        List of validated addresses
        Empty if non validated
    """

    out = []
    for ip in iplist:
        ret = validate_and_return_ip(ip)
        if ret is not None:
            out.append(ret)
    return out

def validate_port(ports):
    """Validate a port string supplied by the user

    Parameters
    ----------
    ports : str
    	Must be: the string all
        A valid service name in /etc/services
        A numeric port number
        A comma separated list of numbers or names
        	converted to a list for blacklist code use

    Returns
    -------
    tuple
        bool True/False
            True if OK, False if error
        str
            Returned value or  Error
    """

    ports = ports.strip()
    if not any(ports):
        return False, 'Ports cannot be empty'
    plist = (l.strip() for l in ports.split(','))
    slist = (l for l in plist if l != '')
    out = []
    for p in slist:
        if p == 'all':
            return True, 'all'
        try:
            pi = int(p)
            out.append(pi)
        except ValueError:
            try:
                pi = socket.getservbyname(p)
                out.append(pi)
            except OSError:
                return False, f'Unknown service name found: {p}'
    # make ordered list with no duplicates
    # ports are already ints
    ordered = sorted(list(set(out)))
    return True, ordered

def validate_pattern(pattern):
    """Validate a pattern suppied by the user

    Parameters
    ----------
    pattern : str

    Returns
    -------
    tuple
        bool True/False
            True if OK, False if error
        str
            Returned value or  Error
    """

    pattern = pattern.strip()
    if not any(pattern):
        return False, 'Pattern cannot be empty'
    if ',' in pattern \
       or ' ' in pattern:
        return False, 'Pattern cannot contain spaces or commas'
    return True, pattern
