"""One asset inventory, explicit Host ID bindings, encrypted SSH credentials."""
import base64
import hashlib
import io
import ipaddress
import re
import paramiko
from pydantic import BaseModel, ConfigDict, Field

DEVICE_TYPES = {'linux','windows','vmware','network','other','unknown'}
USER_RE = re.compile(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,31}\Z')
NETWORKS = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7'))

def address(value):
    ip = ipaddress.ip_address(value.strip())
    if getattr(ip, 'scope_id', None) or not any(ip.version == n.version and ip in n for n in NETWORKS):
        raise ValueError('SSH 地址仅允许 RFC1918/ULA 内网 IP，不接受域名、回环或公网地址')
    return str(ip)

def host_key(value):
    fields = value.strip().split()
    if len(fields)<2 or len(value)>4096 or '\n' in value.strip() or fields[0] not in {'ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256'}:
        raise ValueError('请填写经独立核验的 SSH 主机公钥')
    try:
        raw = base64.b64decode(fields[1], validate=True)
        if paramiko.PKey.from_type_string(fields[0], raw).asbytes()!=raw:
            raise ValueError()
    except Exception:
        raise ValueError('SSH 主机公钥格式无效') from None
    return ' '.join(fields[:2])

def fingerprint(value):
    return 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(host_key(value).split()[1])).digest()).decode().rstrip('=') if value else ''

def private_key(value, passphrase=''):
    if not 32<=len(value)<=20000:
        raise ValueError('SSH 私钥长度无效')
    for kind in (paramiko.Ed25519Key,paramiko.RSAKey,paramiko.ECDSAKey):
        try:
            return kind.from_private_key(io.StringIO(value.strip()+'\n'), password=passphrase or None)
        except Exception:
            pass
    raise ValueError('无法读取 SSH 私钥，请检查格式和口令')

class AssetInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1,max_length=160)
    zabbix_hostid: str|None = Field(default=None,pattern=r'^[0-9]{1,32}$')
    device_type: str = 'unknown'
    address: str = Field(default='',max_length=64)
    ssh_port: int = Field(default=22,ge=1,le=65535)
    username: str = Field(default='ai-diagnostic',max_length=32)
    host_key: str = Field(default='',max_length=4096)
    credential_id: int|None = Field(default=None,ge=1)
    proxy_id: int|None = Field(default=None,ge=1)
    diagnostic_mode: str = 'standard'
    privileged_approved: bool = False
    enabled: bool = True
    group_ids: list[int] = Field(default_factory=list,max_length=50)

    def checked(self):
        if not self.name.strip() or self.device_type not in DEVICE_TYPES:
            raise ValueError('资产名称或设备类型无效')
        if self.diagnostic_mode not in {'standard','privileged'} or not USER_RE.fullmatch(self.username):
            raise ValueError('诊断模式或 SSH 用户名无效')
        if self.username=='root' and self.diagnostic_mode!='privileged':
            raise ValueError('标准免 Agent 模式禁止 root；请使用专用低权限账号')
        if self.diagnostic_mode=='privileged' and not self.privileged_approved:
            raise ValueError('特权模式必须由管理员确认目标强制命令网关已正确限制')
        if self.address: self.address = address(self.address)
        if self.host_key: self.host_key = host_key(self.host_key)
        if self.device_type!='linux' and (self.credential_id or self.host_key or self.privileged_approved):
            raise ValueError('第一阶段 SSH 诊断只适用于明确登记的 Linux 资产')
        return self

def row_dict(row, cur):
    return dict(zip((x[0] for x in cur.description),row)) if row else None

def get_asset(asset_id=None, *, zabbix_hostid=None):
    from ..main import connection
    with connection() as db:
        cur = db.execute('SELECT * FROM assets WHERE '+('id=?' if asset_id is not None else 'zabbix_hostid=?'),
                         (asset_id if asset_id is not None else zabbix_hostid,))
        return row_dict(cur.fetchone(),cur)

def save_asset(body, actor, asset_id=None):
    from ..main import connection
    from ..security.rbac import audit
    body = body.checked()
    values = body.model_dump(exclude={'group_ids'})
    with connection() as db:
        if asset_id is None:
            asset_id=db.execute('INSERT INTO assets('+','.join(values)+') VALUES ('+','.join('?' for _ in values)+')',tuple(values.values())).lastrowid
        else:
            cur=db.execute('UPDATE assets SET '+','.join(k+'=?' for k in values)+',revision=revision+1,updated_at=CURRENT_TIMESTAMP,last_test_status=NULL WHERE id=?',(*values.values(),asset_id))
            if not cur.rowcount: raise ValueError('资产不存在')
        db.execute('DELETE FROM asset_group_members WHERE asset_id=?',(asset_id,))
        db.executemany('INSERT INTO asset_group_members VALUES (?,?)',((asset_id,gid) for gid in set(body.group_ids)))
    audit(actor,'asset_saved',asset_id)
    return get_asset(asset_id)

def asset_page(page=1,page_size=25,query='',device_type='all',group_id=None):
    from ..main import connection
    clauses,values=['1=1'],[]
    if query:
        clauses.append('(instr(lower(name),lower(?))>0 OR instr(address,?)>0 OR zabbix_hostid=?)'); values.extend((query,query,query))
    if device_type!='all': clauses.append('device_type=?'); values.append(device_type)
    if group_id: clauses.append('id IN (SELECT asset_id FROM asset_group_members WHERE group_id=?)'); values.append(group_id)
    where=' WHERE '+' AND '.join(clauses)
    with connection() as db:
        total=db.execute('SELECT COUNT(*) FROM assets'+where,values).fetchone()[0]
        cur=db.execute('SELECT * FROM assets'+where+' ORDER BY id DESC LIMIT ? OFFSET ?',(*values,page_size,(page-1)*page_size))
        rows=[row_dict(row,cur) for row in cur.fetchall()]
        for row in rows:
            row['group_ids']=[r[0] for r in db.execute('SELECT group_id FROM asset_group_members WHERE asset_id=?',(row['id'],))]
            row['fingerprint']=fingerprint(row['host_key'])
    return {'items':rows,'total':total,'page':page,'page_size':page_size}

def save_credential(name,raw,passphrase,actor,credential_id=None):
    from ..main import connection,cipher
    from ..security.rbac import audit
    private_key(raw,passphrase)
    encrypted=cipher().encrypt(raw.encode()).decode(),cipher().encrypt(passphrase.encode()).decode()
    rotating=credential_id is not None
    with connection() as db:
        if rotating:
            if not db.execute('UPDATE ssh_credentials SET name=?,private_key=?,passphrase=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?',(name,*encrypted,credential_id)).rowcount:
                raise ValueError('凭据不存在')
        else:
            credential_id=db.execute('INSERT INTO ssh_credentials(name,private_key,passphrase) VALUES (?,?,?)',(name,*encrypted)).lastrowid
    audit(actor,'credential_rotated' if rotating else 'credential_created',credential_id)
    return {'id':credential_id,'name':name,'key_configured':True}

def credential_key(credential_id):
    from ..main import connection,cipher
    with connection() as db:
        row=db.execute('SELECT private_key,passphrase FROM ssh_credentials WHERE id=?',(credential_id,)).fetchone()
    if not row: raise ValueError('SSH 凭据未配置')
    return private_key(cipher().decrypt(row[0].encode()).decode(),cipher().decrypt(row[1].encode()).decode())

def infer_device(host):
    tags={t.get('tag'):str(t.get('value','')).lower() for t in host.get('tags',[]) if isinstance(t,dict)}
    if tags.get('aiops.device_type') in DEVICE_TYPES: return tags['aiops.device_type']
    os_name=str((host.get('inventory') or {}).get('os','')).lower()
    for kind,words in [('windows',('windows',)),('vmware',('vmware','esxi','vcenter')),('network',('huawei','vrp','cisco','comware')),('linux',('linux',))]:
        if any(w in os_name for w in words): return kind
    return 'unknown'
