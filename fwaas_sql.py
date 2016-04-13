import sqlite3
from neutron_fwaas.services.firewall.agents.fwaas_agent \
    import fwaas_utils as nf_utils
from oslo_log import log as logging
LOG = logging.getLogger(__name__)

def sql_init_routerip():
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("create table if not exists routerip(uuid varchar(128) primary key, ip varchar(128))")
    conn.commit()
    LOG.debug('reate tables about the routerip')
    conn.close()

def sql_init_router(router_id):
    uuid=router_id[0:8]
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("create table if not exists r"+uuid+"_tag_rif(pid integer , rif varchar(128) primary key)")
    conn.commit()
    LOG.debug('reate tables about the router')
    conn.close()

def sql_store_routerip(uuid,ip):
    uuid=str(uuid)
    ip=str(ip)
    t=(uuid,ip)
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("insert into routerip values (?,?)", t)
    conn.commit()
    LOG.debug('insert routerip values into database')
    conn.close()

def sql_store_tagrif(tag,rif,router_id):
    uuid=router_id[0:8]
    tag=int(tag)
    rif=str(rif)
    t=(tag,rif)
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("insert into r"+uuid+"_tag_rif values (?,?)", t)
    conn.commit()
    LOG.debug('insert tag_rif values into database')
    conn.close()


def sql_del_tagrif(rif,router_id):
    uuid=router_id[0:8]
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("delete from r"+uuid+"_tag_rif where rif='"+rif+"'")
    conn.commit()
    LOG.debug('deleted id_name values from database')
    conn.close()

def sql_del_routerip(uuid):
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("delete from routerip where uuid='"+uuid+"'")
    conn.commit()
    LOG.debug('deleted id_name values from database')
    conn.close()

def sql_del_routertables(router_id):
    uuid=router_id[0:8]
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    conn.execute("DROP TABLE IF EXISTS r"+uuid+"_tag_rif")
    conn.commit()
    uuid=router_id[0:8]
    sql_del_routerip(uuid)
    LOG.debug('delete router information from database')
    conn.close()


def sql_tag(rif,router_id):
    uuid=router_id[0:8]
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    cu=conn.execute("select pid from r"+uuid+"_tag_rif where rif='"+rif+"'")
    row=cu.fetchone()
    try:
        tag=row[0]
    except:
        return 'none'
    tag=str(tag)
    LOG.debug('get tag from database')
    conn.close()
    return tag

def sql_rif(tag,router_id):
    uuid=router_id[0:8]
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    cu=conn.execute("select name from r"+uuid+"_tag_rif where pid='"+tag+"'")
    row=cu.fetchone()
    try:
        rif=row[0]
    except:
        return 'none'
    LOG.debug('get rif from database')
    conn.close()
    return rif

def sql_ip(uuid):
    conn = sqlite3.connect(nf_utils.DATABASE_ADDR)
    cu=conn.execute("select ip from routerip where uuid='"+uuid+"'")
    row=cu.fetchone()
    try:
        ip=row[0]
    except:
        return 'none'
    LOG.debug('get ip from database')
    conn.close()
    return ip