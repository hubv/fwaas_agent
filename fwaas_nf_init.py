import json
import socket
import time
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NF_init():

    def __init__(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)

    def _socket_conn(self,sockfile):
        self.sock.connect(sockfile)
        time.sleep(3)

#    def _nf_set_gateway(self,gip):
#        self.sock.send('{"execute": "guest-network-set-gateway","arguments": {"ip-address": ["'+gip+'"]}}')
#        data=json.loads(self.sock.recv(2048))
#        if data['return']==0:
#            print 'set gateway successfully'
#        else:
#            print 'set gateway error'

    def _nf_set_authorization(self,ip,eip):
        self.sock.send('{"execute": "guest-set-authorization","arguments":\
        {"local-ip": "'+ip+'","espc-ip":{ "in-use":"yes", "ip-address":"'+eip+'"}}}')
        data=json.loads(self.sock.recv(2048))
        if data['return']==0:
            LOG.debug('set authorization successfully')
        else:
            print 'set authorization error'

    def _nf_set_restserver(self,ip):
        self.sock.send('{"execute": "guest-set-restapi","arguments":\
        {"rest-server": {"interface-name":"M","ip-address":"'+ip+'","multi-ip-\
        address":"0","port":"8000","server-type":"http","status":"enable"}}}')
        data=json.loads(self.sock.recv(2048))
        if data['return']==0:
            LOG.debug('set restserver successfully')
        else:
            LOG.debug('set restserver error')

    def _nf_set_rest_user(self,token):
        self.sock.send('{"execute": "guest-set-restapi","arguments"\
        :{"rest-users": [{"ip-address":"*","name":"fwaas"\
        ,"status":"enabled","token":"'+token+'"}]}}')
        data=json.loads(self.sock.recv(2048))
        if data['return']==0:
            LOG.debug('set rest user successfully')
        else:
            LOG.debug('set restuser error')

    def _nf_set_passwd(self,username,password):
        self.sock.send('{"execute": "guest-login-set-user","arguments": {"username": "'+username+'","passwd": "'+password+'"}}')
        data=json.loads(self.sock.recv(2048))
        if data['return']==0:
            LOG.debug('set user and password successfully')
        else:
            LOG.debug('set user and password error')

    def nf_init(self, sockfile, ip, eip, username, password):
        self._socket_conn(sockfile)
#        self._nf_set_gateway(gip)
        self._nf_set_authorization(ip,eip)
        self._nf_set_passwd(username,password)
        self._nf_set_restserver(ip)
#        self._nf_set_rest_user(token)
        self.sock.close()
        LOG.debug('NF initiated successfully')



