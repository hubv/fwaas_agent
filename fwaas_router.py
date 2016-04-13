import sys
import eventlet
eventlet.monkey_patch()
import os

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import exceptions as n_exc
from neutron.i18n import _LE

from neutron.agent.common import config
from neutron.agent.l3 import agent
from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import ha
from neutron.agent.l3 import router_info
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import config as common_config
from neutron.common import topics
from neutron import service as neutron_service
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from neutron.agent.metadata import config as metadata_config
from neutron_fwaas.services.firewall.agents.l3reference \
    import firewall_l3_agent
from neutron_fwaas.services.firewall.agents.fwaas_agent import fwaas_api
from neutron_fwaas.services.firewall.agents.fwaas_agent \
    import fwaas_utils as nf_utils
from neutron_fwaas.services.firewall.agents.fwaas_agent \
    import fwaas_sql as sql
from neutron_fwaas.services.firewall.agents.fwaas_agent \
    import fwaas_nf_init as init

LOG = logging.getLogger(__name__)

INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
REST_URL_PREFIX = '/api/v1'

class fwaasL3NATAgent(agent.L3NATAgent,
                        firewall_l3_agent.FWaaSL3AgentRpcCallback):
    def __init__(self, host, conf=None):
        LOG.debug('fwaasL3NATAgent: __init__')
        self.rest = fwaas_api.fwaasRestAPI()
        super(fwaasL3NATAgent, self).__init__(host, conf)

    def get_internal_ports(self, ri):
        internal_ports = []
        if '_interfaces' in ri.router:
            for i in range(len(ri.router['_interfaces'])):
                port = ri.router['_interfaces'][i]
                internal_ports.append(port)
            return  internal_ports
        else:
            return []

    def get_ex_gw_port(self, ri):
        ex_gw_port = ri.router['gw_port']
        return ex_gw_port

    def get_floatingips(self, ri):
        floatingips=[]
        if '_floatingips' in ri.router:
            for i in range(len(ri.router['_floatingips'])):
                floatingip= ri.router['_floatingips'][i]
                floatingips.append(floatingip)
            return floatingip
        else:
            return []

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]



    def _safe_router_removed(self, router_id):
        """Try to delete a router and return True if successful."""
        try:
            uuid=router_id[0:8]
            cmd="ps aux|grep "+uuid+"|awk '{print $2}'|xargs sudo kill -9"
            os.system(cmd)
            LOG.debug('shut down NF seccessfully')
            cmd="ovs-vsctl del-br br-in-"+uuid
            os.system(cmd)
            cmd="ovs-vsctl del-br br-out-"+uuid
            os.system(cmd)
            cmd="ovs-vsctl del-port br-con nf-"+uuid+"-0"
            os.system(cmd)
            ri = self.router_info.get(router_id)
            if ri:
                for p in self.get_internal_ports(ri):
                    dev = self.get_internal_device_name(p['id'])
                    if sql.sql_tag(dev,router_id)!='none':

                        interface_name=dev+'-p1'
                        cmd="ovs-vsctl del-port br-int "+interface_name
                        res = os.popen(cmd).read()
                        if res=='':
                            LOG.debug('delete ovs br-int port seccessfully')
                gwport=self.get_ex_gw_port(ri)
                if gwport!=None:
                    id=gwport['id']
                    dev=self.get_external_device_name(id)
                    interface_name=dev+'-p1'
                    cmd="ovs-vsctl del-port br-ex "+interface_name
                    res = os.popen(cmd).read()
                    if res=='':
                        LOG.debug('delete ovs br-ex port seccessfully')
                    addr = "%s/%s" %(gwport["fixed_ips"][0]["ip_address"], gwport["fixed_ips"][0]["prefixlen"])
                    cmd='sudo ip netns exec qrouter-'+router_id+' ip -4 addr add '+addr+' dev '+dev
                    res = os.popen(cmd).read()
                    if res=='':
                        LOG.debug('set ip for device seccessfully')

                self._router_removed(router_id)
            sql.sql_del_routertables(router_id)

        except Exception:
            LOG.exception(_LE('Error while deleting router %s'), router_id)
            return False
        else:
            return True


    def _nf_pif_2_tag(self, pif, router_id):
        return sql.sql_tag(pif, router_id)

    def _nf_set_interface_ip(self, pif, cidr, router_id):
        LOG.debug("_nf_set_interface_ip: %(pif)s %(cidr)s",
                  {'pif': pif, 'cidr': cidr})
        self.change_rest_url(router_id)
        tag = self._nf_pif_2_tag(pif,router_id)
        body = {
           'parentInterface': 'G1/2' ,
            'vlanId': tag ,
            'mtu': '1500',
            'zone': 'Intranet',
            'primaryIp': cidr ,
            'managementProfile': 'default' ,
            'secondaryIp': []
        }
        self.rest.rest_api('POST', nf_utils.REST_URL_INTRA, body)

    def _nf_set_route(self, lif, cidr, gateway):
        name = '%s_%s' % (cidr, lif)
        LOG.debug("_nf_set_route: %(lif)s %(cidr)s",
                  {'lif': lif, 'cidr': cidr})

        body = {
            "name":name,
            'dstNet':cidr,
            "interface":lif,
            'gateway':gateway,
            "enabled":"true"
            }
        self.rest.rest_api('POST', nf_utils.REST_URL_ROUTE, body)

    def _nf_config_intranet(self, ri):
        # add new internal ports to intranet zone
        router_id=ri.router['id']
        self.change_rest_url(router_id)
        internal_ports=self.get_internal_ports(ri)
        for p in internal_ports:
            if p['admin_state_up']:
                pif = self.get_internal_device_name(p['id'])
                if pif:
                    addr = "%s/%s" %(p["fixed_ips"][0]["ip_address"], p["fixed_ips"][0]["prefixlen"])
                    self._nf_set_interface_ip(pif, addr, router_id)
                    #self._nf_set_interface_ip(pif, p['subnets'][0]['cidr'], router_id)
                    tag = self._nf_pif_2_tag(pif,router_id)
                    lif='G1/2.'+tag
                    self._nf_set_route(lif,p['subnets'][0]['cidr'],p["fixed_ips"][0]["ip_address"])
                    self.rest.commit()

    def _nf_config_extranet(self, ri):
        # add new gateway ports to extranet zone
        router_id=ri.router['id']
        self.change_rest_url(router_id)
        ex_gw_port=self.get_ex_gw_port(ri)
        if ex_gw_port:
            LOG.debug("_nf_config_untrusted_zone: gw=%r", ex_gw_port)
            addr = "%s/%s" %(ex_gw_port["fixed_ips"][0]["ip_address"], ex_gw_port["fixed_ips"][0]["prefixlen"])
            body = {
                'interface': 'G1/1',
                'zone': 'Extranet',
                'primaryIp': addr,
                'managementProfile': 'default' ,
                'secondaryIp': []
                }
            self.rest.rest_api('POST', nf_utils.REST_URL_INTF, body)
            gateway=ex_gw_port['subnets'][0]['gateway_ip']
            self._nf_set_route('G1/1',ex_gw_port['subnets'][0]['cidr'],gateway)
            self.rest.commit()


    def _make_address(self, ri, net):

        router_id=ri.router['id']
        self.change_rest_url(router_id)
        body = {
                'name': net,
                'net': net,
                'ip': net
                }

        if net.find('/')==-1:
            data=self.rest.rest_api('POST', nf_utils.REST_URL_CONF_ADDR_2, body)
        else:
            data=self.rest.rest_api('POST', nf_utils.REST_URL_CONF_ADDR_1, body)
        self.rest.commit()
        pid=data['body']['id']
        return pid

    def _nf_config_router_snat_rules(self, ri):

        LOG.debug('_nf_config_router_snat_rules: %s', ri.router['id'])
        router_id=ri.router['id']
        self.change_rest_url(router_id)
        prefix = nf_utils.get_snat_rule_name(ri)
        self.rest.del_cfg_objs(nf_utils.REST_URL_CONF_SNAT_RULE, prefix)

        if not ri._snat_enabled:
            return
        internal_ports=self.get_internal_ports(ri)
        for idx, p in enumerate(internal_ports):
            if p['admin_state_up']:
                pif = self.get_internal_device_name(p['id'])
                if pif:
                    net = p['subnets'][0]['cidr']
                    addr=self._make_address(ri, net)

                    name='%s_%d' % (prefix, idx)
                    body = {
                         'name': name,
                         'srcZone': 'Intranet',
                         'dstZone': 'Extranet',
                         'srcNet': addr or '110001',
                         'dstNet': '110001',
                         'interface': 'G1/1',
                         'easyIp': 'true'
                        }
                    data=self.rest.rest_api('POST',
                                       nf_utils.REST_URL_CONF_SNAT_RULE,
                                       body)
        if internal_ports:
            self.rest.commit()

    def _nf_config_floating_ips(self, ri):

        LOG.debug('_nf_config_floating_ips: %s', ri.router['id'])
        router_id=ri.router['id']
        self.change_rest_url(router_id)
        prefix = nf_utils.get_dnat_rule_name(ri)
        self.rest.del_cfg_objs(nf_utils.REST_URL_CONF_DNAT_RULE, prefix)

        # add new dnat rules
        floating_ips=self.get_floatingips(ri)
        for idx, fip in enumerate(floating_ips):
            extraobj = self._make_address(ri, fip['floating_ip_address'])
            intraobj = self._make_address(ri, fip['fixed_ip_address'])
            name = '%s_%d' % (prefix, idx)
            body = {
            'name': name,
            'interface':'G1/1',
            'intraObject': intraobj,
            'extraObject': extraobj,
            'type':'map',
            'detectIntraObject':'false',
            'detectIntraIp':'false'
            }
            self.rest.rest_api('POST', nf_utils.REST_URL_CONF_DNAT_RULE, body)
        if ri.floating_ips:
            self.rest.commit()



    def _handle_router_snat_rules(self, ri, ex_gw_port,
                                  interface_name, action):
        return

    def _send_gratuitous_arp_packet(self, ri, interface_name, ip_address):
        return


    def _update_routing_table(self, ri, operation, route):
        return

    def change_rest_url(self,router_id):
        uuid=router_id[0:8]
        ip=sql.sql_ip(uuid)
        self.rest.server=ip
        self.rest.URL="http://" + self.rest.server + ":" + self.rest.port+ REST_URL_PREFIX




    def _process_router_if_compatible(self, router):
        ri = router_info.RouterInfo(router_id=router.get('id'), router=router,
                                    agent_conf=self.conf,
                                    interface_driver=self.driver)
        LOG.debug("process_router: %s", ri.router['id'])

        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_LE("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        # If namespaces are disabled, only process the router associated
        # with the configured agent id.
        if (not self.conf.use_namespaces and
            router['id'] != self.conf.router_id):
            raise n_exc.RouterNotCompatibleWithAgent(router_id=router['id'])

        # Either ex_net_id or handle_internal_only_routers must be set
        ex_net_id = (router['external_gateway_info'] or {}).get('network_id')
        if not ex_net_id and not self.conf.handle_internal_only_routers:
            raise n_exc.RouterNotCompatibleWithAgent(router_id=router['id'])

        # If target_ex_net_id and ex_net_id are set they must be equal
        target_ex_net_id = self._fetch_external_net_id()
        if (target_ex_net_id and ex_net_id and ex_net_id != target_ex_net_id):
            # Double check that our single external_net_id has not changed
            # by forcing a check by RPC.
            if ex_net_id != self._fetch_external_net_id(force=True):
                raise n_exc.RouterNotCompatibleWithAgent(
                    router_id=router['id'])

        if router['id'] not in self.router_info:
            self._process_added_router(router)
        else:
            self._process_updated_router(router)



        router_id=ri.router['id']
        uuid=router_id[0:8]
        sql.sql_init_router(router_id)
        self.brin='br-in-'+router_id[0:8]
        self.brout='br-out-'+router_id[0:8]


        self.change_rest_url(router_id)
        internal_ports=self.get_internal_ports(ri)
        for p in internal_ports:
            if p['admin_state_up']:
                dev = self.get_internal_device_name(p['id'])

                int_patch_interface=dev+'-p1'
                in_patch_interface=dev+'-p2'

                cmd='ip netns exec qrouter-'+router_id+' ifconfig '+dev+' 0'
                res = os.popen(cmd).read()
                if res=='':
                    LOG.debug('delete ip from device seccessfully')

                #get tag
                cmd="ovs-vsctl get port "+dev+" tag"
                tag = os.popen(cmd).read()
                tag=tag.strip('\n')
                br='br-in-'+uuid
                if sql.sql_tag(dev,router_id)=='none':
                    sql.sql_store_tagrif(tag,dev,router_id)
                    cmd="ovs-vsctl add-port br-int "+int_patch_interface+\
                        " -- set Interface "+int_patch_interface+" \
                    type=patch -- set Interface "+int_patch_interface+" options:peer="+in_patch_interface

                    res = os.popen(cmd).read()
                    if res=='':
                        LOG.debug('add ovs port seccessfully')


                    cmd="ovs-vsctl add-port "+br+" "+in_patch_interface+\
                        " -- set Interface "+in_patch_interface+" type=patch \
                    -- set Interface "+in_patch_interface+" options:peer="+int_patch_interface
                    res = os.popen(cmd).read()
                    if res=='':
                        LOG.debug('link nf bridge seccessfully')


                    cmd="ovs-vsctl set port "+in_patch_interface+" trunk="+tag
                    res = os.popen(cmd).read()
                    if res=='':
                        LOG.debug('set trunk port seccessfully')



        self.rest.auth()
        self._nf_config_intranet(ri)
        self._nf_config_extranet(ri)
        self._nf_config_router_snat_rules(ri)
        self._nf_config_floating_ips(ri)

        if 'gw_port' in ri.router:
            ex_gw_port=self.get_ex_gw_port(ri)
            gw_dev_id=ex_gw_port['id']
            gw_dev=self.get_external_device_name(gw_dev_id)
            cmd='ip netns exec qrouter-'+router_id+' ifconfig '+gw_dev+' 0'
            os.system(cmd)
            cmd='ip netns exec qrouter-'+router_id+' ifconfig '+gw_dev+' 0'
            res = os.popen(cmd).read()
            if res=='':
                LOG.debug('delete ip from device seccessfully')



class fwaasL3NATAgentWithStateReport(fwaasL3NATAgent,
                                       agent.L3NATAgentWithStateReport):
    pass


def main():
    conf = cfg.CONF
    conf.register_opts(l3_config.OPTS)
    conf.register_opts(ha.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf.register_opts(metadata_config.DRIVER_OPTS)
    conf.register_opts(metadata_config.SHARED_OPTS)




    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron_fwaas.services.firewall.agents.fwaas.'
                'fwaas_router.fwaasL3NATAgentWithStateReport')
    service.launch(conf, server).wait()
