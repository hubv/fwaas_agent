ROUTER_OBJ_PREFIX = 'r-'
OBJ_PREFIX_LEN = 8
SNAT_RULE = '_snat'
DNAT_RULE = '_dnat'
ROUTER_POLICY = '_p'
DATABASE_ADDR= '/usr/lib/python2.7/site-packages/neutron_fwaas/services/firewall/agents/fwaas/fw.db'

REST_URL_COMMIT = '/system/commit'
REST_URL_INTF = '/network/interface/layer3/'
REST_URL_INTRA = '/network/interface/layer3Sub/'
REST_URL_INTF_MAP = '/operation/interface/'
REST_URL_CONF_SNAT_RULE = '/policy/nat/snat'
REST_URL_CONF_DNAT_RULE = '/policy/nat/dnat'
REST_URL_CONF_POLICY = '/policy/security'
REST_URL_CONF_ADDR_1 = '/object/networks/network'
REST_URL_CONF_ADDR_2 = '/object/networks/node'
REST_URL_CONF_SERVICE = '/object/service/custom'
REST_URL_ROUTE = '/network/route/static/'

def get_router_object_prefix(ri):
    return ROUTER_OBJ_PREFIX + ri.router['id'][:OBJ_PREFIX_LEN]

def get_firewall_object_prefix(ri, fw):
    return get_router_object_prefix(ri) + '-' + fw['id'][:OBJ_PREFIX_LEN]

def get_snat_rule_name(ri):
    return get_router_object_prefix(ri) + SNAT_RULE

def get_dnat_rule_name(ri):
    return get_router_object_prefix(ri) + DNAT_RULE

def get_router_policy_name(ri):
    return get_router_object_prefix(ri) + ROUTER_POLICY

def get_firewall_policy_name(ri, fw, rule):
    return get_firewall_object_prefix(ri, fw) + rule['id'][:OBJ_PREFIX_LEN]

