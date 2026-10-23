"""Pinned direct/jump SSH with cross-process leases and bounded channel reads."""
import base64
import socket
import threading
import time
import uuid
from contextlib import contextmanager

import paramiko
from .. import inventory
from ..security.redact import redact
from .actions import build,gateway_request

class DiagnosticError(RuntimeError):
    pass

def _connect(client,address,port,username,host_key,key,sock=None):
    key_type,b64=inventory.host_key(host_key).split()
    expected=paramiko.PKey.from_type_string(key_type,base64.b64decode(b64))
    client.get_host_keys().add(address if port==22 else f'[{address}]:{port}',key_type,expected)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(hostname=inventory.address(address),port=port,username=username,pkey=key,
        allow_agent=False,look_for_keys=False,timeout=5,banner_timeout=5,auth_timeout=5,channel_timeout=5,sock=sock)

@contextmanager
def lease(asset_id):
    from ..main import connection,read_setting
    ident=uuid.uuid4().hex
    limit=max(1,min(16,int(read_setting('ssh_concurrency') or 4)))
    with connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS ssh_leases(id TEXT PRIMARY KEY, asset_id INTEGER UNIQUE, expires INTEGER NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM ssh_leases WHERE expires<?',(int(time.time()),))
        if db.execute('SELECT COUNT(*) FROM ssh_leases').fetchone()[0]>=limit:
            raise DiagnosticError('SSH 并发已达上限，请稍后重试')
        try: db.execute('INSERT INTO ssh_leases VALUES (?,?,?)',(ident,asset_id,int(time.time())+120))
        except Exception: raise DiagnosticError('此主机已有诊断正在执行') from None
    try: yield
    finally:
        with connection() as db: db.execute('DELETE FROM ssh_leases WHERE id=?',(ident,))

def execute(asset_id,action,service=None,time_window=30,cancelled=lambda:False):
    from ..main import connection,read_setting
    asset=inventory.get_asset(asset_id)
    if not asset or not asset['enabled'] or asset['device_type']!='linux':
        raise ValueError('目标不是已启用的 Linux 资产')
    # Validate the complete action before opening any network connection.
    command=build(action,service,time_window)
    if asset['diagnostic_mode']=='privileged':
        if not asset['privileged_approved']: raise ValueError('特权模式尚未授权')
        command=gateway_request(action,service,time_window)
    else:
        if asset['username']=='root': raise ValueError('标准模式禁止 root')
        command="PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; if [ \"$(id -u)\" = 0 ]; then printf 'AIOPS_UID_ZERO_DENIED\\n'; exit 78; fi; "+command
    if cancelled(): raise DiagnosticError('任务已取消')
    timeout=max(3,min(30,int(read_setting('ssh_timeout') or 15)))
    client=paramiko.SSHClient(); jump=None; chan=None; timer=None
    started=time.monotonic()
    with lease(asset_id):
        try:
            key=inventory.credential_key(asset['credential_id'])
            tunnel=None
            if asset['proxy_id']:
                with connection() as db:
                    cur=db.execute('SELECT * FROM ssh_proxies WHERE id=?',(asset['proxy_id'],))
                    proxy=inventory.row_dict(cur.fetchone(),cur)
                if not proxy: raise ValueError('跳板配置不存在')
                jump=paramiko.SSHClient()
                _connect(jump,proxy['address'],proxy['port'],proxy['username'],proxy['host_key'],inventory.credential_key(proxy['credential_id']))
                tunnel=jump.get_transport().open_channel('direct-tcpip',(asset['address'],asset['ssh_port']),('127.0.0.1',0),timeout=5)
            _connect(client,asset['address'],asset['ssh_port'],asset['username'],asset['host_key'],key,tunnel)
            chan=client.get_transport().open_session(timeout=5)
            chan.settimeout(5)
            # Paramiko exec acknowledgement can otherwise wait indefinitely.
            timer=threading.Timer(timeout,client.close); timer.daemon=True; timer.start()
            chan.exec_command(command)
            out,err=bytearray(),bytearray(); truncated=False
            deadline=time.monotonic()+timeout
            while True:
                if cancelled(): raise DiagnosticError('任务已取消')
                if time.monotonic()>deadline: raise DiagnosticError('SSH 诊断超时')
                for ready,recv,buf,cap in [(chan.recv_ready,chan.recv,out,32768),(chan.recv_stderr_ready,chan.recv_stderr,err,2048)]:
                    if ready():
                        buf.extend(recv(min(4096,cap+1-len(buf))))
                        if len(buf)>cap: truncated=True; break
                if truncated: break
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready(): break
                time.sleep(.025)
            code=None if truncated else chan.recv_exit_status()
            output=redact(out.decode('utf-8','replace')); stderr=redact(err.decode('utf-8','replace'),2048)
            if code==-1: raise DiagnosticError('SSH 未返回退出状态，可能连接中断或超时')
            if 'AIOPS_UID_ZERO_DENIED' in output: raise DiagnosticError('标准模式目标实际 UID 为 0，已拒绝执行')
            if asset['diagnostic_mode']=='privileged' and not output.startswith('AIOPS_GATEWAY_V1\n'):
                raise DiagnosticError('目标未返回受限网关标识，请验证强制命令配置')
            status='partial' if truncated or 'CAPABILITY_MISSING:' in output or stderr or code not in (0,None) else 'success'
            return {'provider':'linux_ssh','asset_id':asset_id,'action':action,'mode':asset['diagnostic_mode'],
                    'status':status,'output':output,'stderr':stderr,'exit_code':code,'truncated':truncated,
                    'duration_ms':int((time.monotonic()-started)*1000),'asset_revision':asset['revision']}
        except paramiko.BadHostKeyException:
            raise DiagnosticError('SSH 主机公钥不匹配，连接已拒绝；请独立核验目标和跳板公钥') from None
        except paramiko.AuthenticationException:
            raise DiagnosticError('SSH 认证失败，请核验专用密钥和账号') from None
        except (paramiko.SSHException,OSError,EOFError,socket.timeout):
            raise DiagnosticError('SSH 连接失败或超时，请检查网络、sshd、跳板及固定公钥') from None
        finally:
            if timer: timer.cancel(); timer.join()
            if chan: chan.close()
            client.close()
            if jump: jump.close()
