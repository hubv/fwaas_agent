import base64
import traceback
import hashlib, json
import httplib, urlparse
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
from neutron.i18n import _LE
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from neutron_fwaas.services.firewall.agents.fwaas_agent \
    import fwaas_utils as nf_utils

LICENSE = "BSD"

VERSION = "$Id$"

send_data = {'headers':'User-Agent: RESTClient-%s' % VERSION.replace(":", "")}

OPTS = [
    cfg.StrOpt('director', default='192.168.19.91',
               help=_("fwaas director ip")),
    cfg.StrOpt('director_port', default='8000',
               help=_("fwaas director port")),
    cfg.StrOpt('username', default='admin',
               help=_("fwaas director username")),
    cfg.StrOpt('password', default='e48eaa28-e498-11e5-a6e7-0287ad06c8f1', secret=True,
               help=_("fwaas director password")),
    cfg.StrOpt('espc', default='192.168.19.234',
               help=_("fwaas controller ip address")), ]


cfg.CONF.register_opts(OPTS, "fwaas")

LOG = logging.getLogger(__name__)

REST_URL_PREFIX = '/api/v1'


class fwaasAPIException(Exception):
    message = _("An unknown exception.")

    def __init__(self, **kwargs):
        try:
            self.err = self.message % kwargs

        except Exception:
            self.err = self.message

    def __str__(self):
        return self.err


class AuthenticationFailure(fwaasAPIException):
    message = _("Invalid login credential.")


class fwaasRestAPI(object):

    def __init__(self):
        LOG.debug('fwaasRestAPI: started')
        self.user = cfg.CONF.fwaas.username
        self.passwd = cfg.CONF.fwaas.password
        self.server = cfg.CONF.fwaas.director
        self.port = cfg.CONF.fwaas.director_port
        self.espc = cfg.CONF.fwaas.espc
#        self.timeout = 3
#        self.key = ''
        self.URL = "http://" + self.server + ":" + self.port+ REST_URL_PREFIX
    def auth(self):
        if not self.user or not self.passwd: return False
        headers = send_data['headers']
        headers = headers.split("\n")
        headers_dict = {}
        for header in headers:
            parts = header.split(":", 1)
            if len(parts) > 1:
                headers_dict[parts[0]] = parts[1].strip()
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd))[:-1]
        headers_dict['Authorization'] = "Basic %s" % base64string
        headers_string = []
        for key, value in headers_dict.items():
            headers_string.append("%s: %s" % (key, value))
        send_data['headers'] = "\n".join(headers_string)
        return True

    def commit(self):
        self.rest_api('PUT', nf_utils.REST_URL_COMMIT)

    def rest_api(self, method, url, body=None, headers=None):
        url=self.URL+url
        if body:
            data=jsonutils.dumps(body)
        else:
            data=''
        headers = send_data['headers']
        headers = headers.split("\n")
        headers_dict = {}
        for header in headers:
            parts = header.split(":")
        if len(parts) > 1:
            headers_dict[parts[0]] = parts[1].strip()
        urlparts = urlparse.urlparse(url)
        conn = httplib.HTTPConnection(urlparts[1])
        url = "%s?%s" % (urlparts[2], urlparts[4])

        import time
        import random
        timestamp = str(time.time())
        nonce = str(random.randint(0,10000))
        pos = url.find('?')
        query_string = ''
        if pos >=0:
            query_string = url[pos+1:]
            url = url[:pos]
        m1 = hashlib.md5()
        arg_dic = {}
        #get hash1
        hash1_str = url.split('api/v1')[1]
        m1.update(hash1_str)
        hash1_ret = m1.hexdigest()
        #get hash2
        hash2_str = ''
        hash2_ret = ''
        if len(arg_dic) > 0:
            hash2_str = json.dumps(sorted(arg_dic.items(),key=lambda x:x[0]))
            m1 = hashlib.md5()
            m1.update(hash2_str)
            hash2_ret = m1.hexdigest()

        #get hash3
        hash3_str = data
        hash3_ret = ''
        if hash3_str:
            m1 = hashlib.md5()
            m1.update(hash3_str)
            hash3_ret = m1.hexdigest()
        #get signature
        print sorted([hash1_ret, hash2_ret, hash3_ret,self.user,self.passwd , nonce, timestamp])
        hash_all_str = ''.join(sorted([hash1_ret, hash2_ret, hash3_ret, self.user, self.passwd , nonce, timestamp]))
        m2 = hashlib.sha1()
        m2.update(hash_all_str)
        hash_all_ret = m2.hexdigest()

        #get_result
        signature = hash_all_ret
        if not query_string:
            url+='?'
        url = "%ssignature=%s&nonce=%s&timestamp=%s&accountId=%s" %(url, signature, nonce, timestamp, self.user)
        print url
        """Loads the data from the server, using the current settings"""
        try:
            print "#####################"
            print "data_length:%d" %(len(data))
            print data
            print "##########################"
            print headers_dict
        except Exception:
            LOG.error(_LE('fwaasRestAPI: Could not establish HTTP '
                          'connection'))
        conn.request(method, url, data, headers_dict)
        response = conn.getresponse()
        resp = response.read()
        conn.close()
        status = response.status
        reason = response.reason
        #import pdb
        #pdb.set_trace()
        print resp
        print status
        data = None
        if status != 200:
            return {'status': status,
                    'reason': reason,
                    'body': data}


        if resp and resp !='':
            data = json.loads(resp)
        headers = response.getheaders()
        print status
        print reason
        print data
        print headers
        return {'status': status,
                'reason': reason,
                'body': data}

    def del_cfg_objs(self, url, prefix):
        resp = self.rest_api('GET', url)
        if resp and resp['status'] == 200:
            result = resp['body']
            if not result:
                return
            #liuwenmao
            #import pdb
            #pdb.set_trace()
            try:
                if isinstance(result, list):
                    olist = result
                    for o in olist:
                        if o['name'].startswith(prefix):
                            pid=o['id']
                            self.rest_api('DELETE', url + '/' +pid)
                else:
                    o = result
                    if o['name'].startswith(prefix):
                        pid=o['id']
                        self.rest_api('DELETE', url + '/' +pid)
            except Exception as e:
                LOG.error("delete cfg object exception");
                print traceback.format_exc()
            self.commit() 

    def count_cfg_objs(self, url, prefix):
        count = 0
        resp = self.rest_api('GET', url)
        if resp and resp['status'] == 200:
            for o in resp['body']:
                if o['name'].startswith(prefix):
                    count += 1

        return count
