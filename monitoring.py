# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.pool import PoolMeta
import subprocess
import json
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
