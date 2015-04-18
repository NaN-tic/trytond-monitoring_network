# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import sys
import ssl
import subprocess
import json
import nmap
from jsonrpclib import Server as ServerProxy
from trytond.pool import PoolMeta

import pingparser

__all__ = ['CheckPlan']
__metaclass__ = PoolMeta


class CheckPlan:
    __name__ = 'monitoring.check.plan'

    def check_ping(self):
        ip = self.get_attribute('ip')
        ping = subprocess.Popen(["ping", "-c", "3", ip],
            stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        stdout, stderr = ping.communicate()
        try:
            result = pingparser.parse(stdout)
        except Exception, e:
            return [{
                    'result': 'ping_status',
                    'char_value': 'Error',
                    'payload': json.dumps({
                            'stdout': stdout,
                            'stderr': stderr,
                            }),
                    }]
        if result['received'] == 0:
            value = 'Unavailable'
        elif result['sent'] == result['received']:
            value = 'OK'
        else:
            value = 'Warning'

        res = []
        res.append({
                'result': 'ping_status',
                'char_value': value,
                'payload': json.dumps(result),
                })
        res.append({
                'result': 'ping_average',
                'float_value': result['avgping']
                })
        return res

    def check_tryton(self):
        urls = self.get_attribute('tryton_urls')
        urls = urls.split()
        res = []
        for url in urls:
            server = ServerProxy(url, verbose=0)
            try:
                if sys.version_info[:3] < (2, 7, 9):
                    server = xmlrpclib.ServerProxy(uri, allow_none=True)
                else:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    server = xmlrpclib.ServerProxy(uri, allow_none=True,
                        context=ssl_context)
                databases = server.common.db.list(None, None)
            except Exception, e:
                res.append({
                        'result': 'tryton_status',
                        'char_value': 'Error',
                        'label': url,
                        'payload': json.dumps({
                                'exception': str(e),
                                })
                        })
                continue
            res.append({
                    'result': 'tryton_status',
                    'char_value': 'OK',
                    'label': url,
                    'payload': json.dumps({
                            'list': databases,
                            })
                    })
        return res

    def check_open_ports(self):
        '''
        Expected structure in ports attribute:

        protocol:port

        Example:

        TCP:22
        TCP:8000
        '''
        ip = self.get_attribute('ip')
        valid_entries = set()
        entries = [x.strip() for x in self.get_attribute('open_ports').split()]
        for entry in entries:
            if len(entry.split(':')) != 2:
                continue
            protocol, port = entry.split(':')
            valid_entries.add((protocol.upper(), int(port)))

        scanner = nmap.PortScanner()
        #scanner.scan(ip, '1-65535')
        scanner.scan(ip, '25-25')
        # Get ip from scanner as user may have given a URL
        # but scanner results are indexed with ip
        ip = scanner.all_hosts()[0]
        entries = set()
        for protocol in scanner[ip].all_protocols():
            for port in scanner[ip][protocol].keys():
                if protocol.upper() in ('TCP', 'UDP'):
                    entries.add((protocol.upper(), port))
        value = 'OK'
        if entries - valid_entries:
            value = 'Error'
        return [{
                'result': 'open_ports_status',
                'char_value': value,
                'payload': json.dumps({
                        'invalid_ports': list(entries - valid_entries),
                        })
                }]
