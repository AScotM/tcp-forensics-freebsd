#!/usr/bin/env python3
import argparse
import collections
import csv
import dataclasses
import datetime
import decimal
import difflib
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any

VERSION = '1.0.0'
SCHEMA = 'tcp-forensics-bsd/v1'
TCP_STATES = ('CLOSED','LISTEN','SYN_SENT','SYN_RECEIVED','ESTABLISHED','CLOSE_WAIT','FIN_WAIT_1','CLOSING','LAST_ACK','FIN_WAIT_2','TIME_WAIT')
STATE_ALIASES = {'SYN_RCVD':'SYN_RECEIVED','FIN_WAIT1':'FIN_WAIT_1','FIN_WAIT2':'FIN_WAIT_2','SYN_RECEIVED':'SYN_RECEIVED','SYN_SENT':'SYN_SENT','TIME_WAIT':'TIME_WAIT','CLOSE_WAIT':'CLOSE_WAIT','LAST_ACK':'LAST_ACK','ESTABLISHED':'ESTABLISHED','LISTEN':'LISTEN','CLOSED':'CLOSED','CLOSING':'CLOSING'}
COUNTER_WORDS = ('packet','segment','byte','retrans','drop','error','timeout','duplicate','reset','connection','ack','syn','fin','window','keepalive','reorder','challenge','bad','invalid','overflow','fail','received','sent','delivered')
SENSITIVE_WORDS = ('password','secret','private','token','credential','key_material')

class ForensicsError(Exception):
    pass

@dataclasses.dataclass
class Result:
    command: list
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: float
    available: bool
    timed_out: bool = False
    def as_dict(self):
        return dataclasses.asdict(self)

@dataclasses.dataclass
class Observation:
    timestamp: str
    monotonic: float
    kind: str
    data: dict
    def as_dict(self):
        return dataclasses.asdict(self)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(argv, timeout=8, max_bytes=4_000_000):
    exe = shutil.which(argv[0])
    if exe is None:
        return Result(list(argv), 127, '', 'executable unavailable', 0.0, False)
    started = time.monotonic()
    try:
        p = subprocess.run([exe] + list(argv[1:]), capture_output=True, text=True, errors='replace', timeout=timeout, env={**os.environ, 'LC_ALL':'C'})
        return Result(list(argv), p.returncode, p.stdout[:max_bytes], p.stderr[:max_bytes], round((time.monotonic()-started)*1000,3), True)
    except subprocess.TimeoutExpired as e:
        return Result(list(argv), 124, (e.stdout or b'').decode('utf-8','replace') if isinstance(e.stdout,bytes) else (e.stdout or ''), 'command timed out', round((time.monotonic()-started)*1000,3), True, True)
    except OSError as e:
        return Result(list(argv), 126, '', str(e), round((time.monotonic()-started)*1000,3), True)


def safe_number(s):
    try:
        return int(str(s).replace(',',''))
    except (ValueError,TypeError):
        try:
            return float(str(s).replace(',',''))
        except (ValueError,TypeError):
            return None


def pct(n,d):
    return round(n*100/d,3) if d else None


def delta(new,old):
    if isinstance(new,(int,float)) and isinstance(old,(int,float)):
        return new-old
    return None


def rate(new,old,seconds):
    d=delta(new,old)
    return round(d/seconds,5) if d is not None and seconds>0 and d>=0 else None


def quantiles(values):
    values=sorted(x for x in values if isinstance(x,(int,float)) and math.isfinite(x))
    if not values:
        return {}
    def q(p):
        index=(len(values)-1)*p
        lo=math.floor(index)
        hi=math.ceil(index)
        return round(values[lo]+(values[hi]-values[lo])*(index-lo),4)
    return {'count':len(values),'min':values[0],'max':values[-1],'mean':round(statistics.mean(values),4),'median':q(.5),'p90':q(.9),'p95':q(.95),'p99':q(.99),'stdev':round(statistics.pstdev(values),4)}


def entropy(values):
    c=collections.Counter(values)
    total=sum(c.values())
    return round(-sum((v/total)*math.log2(v/total) for v in c.values()),5) if total else 0.0


def read_json(path):
    with open(path,encoding='utf-8') as f:
        return json.load(f)


def write_json(path,obj):
    if not path:
        print(json.dumps(obj,indent=2,sort_keys=True,default=str))
        return
    p=pathlib.Path(path).expanduser()
    p.parent.mkdir(parents=True,exist_ok=True)
    tmp=None
    try:
        with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=str(p.parent),prefix='.tcp-forensics-',delete=False) as f:
            tmp=f.name
            json.dump(obj,f,indent=2,sort_keys=True,default=str)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def append_jsonl(path,obj):
    with open(path,'a',encoding='utf-8') as f:
        f.write(json.dumps(obj,sort_keys=True,default=str)+'\n')


def normalize_state(value):
    value=str(value).upper().replace('-','_').strip()
    return STATE_ALIASES.get(value,value)


def parse_endpoint(raw):
    raw=raw.strip()
    if not raw or raw in ('*','*.*'):
        return {'raw':raw,'address':'*','port':None,'family':'unknown','wildcard':True}
    address=raw
    port=None
    if raw.startswith('[') and ']:' in raw:
        address,_,p=raw[1:].partition(']:')
        port=p
    elif '.' in raw:
        address,_,p=raw.rpartition('.')
        port=p
    elif raw.count(':')==1:
        address,_,p=raw.rpartition(':')
        port=p
    if port is not None:
        port=int(port) if str(port).isdigit() else (None if port=='*' else port)
    family='unknown'
    try:
        family='ipv'+str(ipaddress.ip_address(address.split('%')[0]).version)
    except ValueError:
        if address in ('*','0.0.0.0','::'):
            family='wildcard'
    return {'raw':raw,'address':address,'port':port,'family':family,'wildcard':address in ('*','0.0.0.0','::')}


def parse_sockstat(text):
    rows=[]
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('USER '):
            continue
        parts=line.split()
        if len(parts)<7:
            continue
        user,command,pid,fd,proto,local,foreign=parts[:7]
        if not pid.isdigit():
            continue
        rows.append({'user':user,'command':command,'pid':int(pid),'fd':fd,'protocol':proto,'local':parse_endpoint(local),'remote':parse_endpoint(foreign),'raw':line})
    return rows


def parse_netstat_connections(text):
    rows=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)<6 or not re.match(r'^tcp[46]?$',parts[0],re.I):
            continue
        state=normalize_state(parts[-1])
        if state not in TCP_STATES:
            continue
        rows.append({'protocol':parts[0],'recv_q':safe_number(parts[1]),'send_q':safe_number(parts[2]),'local':parse_endpoint(parts[3]),'remote':parse_endpoint(parts[4]),'state':state,'raw':line})
    return rows


def parse_netstat_stats(text):
    entries=[]
    section='general'
    for line in text.splitlines():
        if not line.strip():
            continue
        if line and not line[0].isspace() and line.rstrip().endswith(':'):
            section=line.strip().rstrip(':').lower()
            continue
        m=re.match(r'^\s*([\d,]+)\s+(.+?)\s*$',line)
        if m:
            entries.append({'section':section,'value':int(m.group(1).replace(',','')),'label':m.group(2).strip(),'raw':line.strip()})
    return entries


def parse_sysctl(text):
    result={}
    for line in text.splitlines():
        if ': ' in line:
            key,value=line.split(': ',1)
        elif '=' in line:
            key,value=line.split('=',1)
        else:
            continue
        key=key.strip()
        value=value.strip()
        if key:
            n=safe_number(value)
            result[key]=n if n is not None else value
    return result


def parse_interfaces(text):
    result=[]
    current=None
    for line in text.splitlines():
        if line and not line[0].isspace() and ': flags=' in line:
            if current:
                result.append(current)
            name=line.split(':',1)[0]
            current={'name':name,'addresses':[],'flags':line.split('flags=',1)[-1].split('>',1)[0].split('<')[-1].split(',') if '<' in line else [],'raw':line}
        elif current and line.lstrip().startswith(('inet ','inet6 ')):
            p=line.split()
            if len(p)>1:
                current['addresses'].append({'family':p[0],'address':p[1]})
    if current:
        result.append(current)
    return result


def parse_routes(text):
    routes=[]
    family='unknown'
    for line in text.splitlines():
        if line.startswith('Internet6:'):
            family='ipv6'
        elif line.startswith('Internet:'):
            family='ipv4'
        parts=line.split()
        if len(parts)>=4 and not line.startswith(('Destination','Routing','Internet','default gateway')) and family!='unknown':
            if parts[0].startswith(('---','Flags','Expire')):
                continue
            routes.append({'family':family,'destination':parts[0],'gateway':parts[1],'flags':parts[2],'interface':parts[3] if len(parts)>3 else None,'raw':line})
    return routes


def parse_vmstat(text):
    lines=[x.split() for x in text.splitlines() if x.strip()]
    if len(lines)<2:
        return {}
    header=lines[-2]
    values=lines[-1]
    if len(header)==len(values):
        return {k:safe_number(v) if safe_number(v) is not None else v for k,v in zip(header,values)}
    return {'raw':text}


def filter_connections(rows,args):
    filtered=[]
    for r in rows:
        if getattr(args,'state',None) and normalize_state(args.state)!=r['state']:
            continue
        if getattr(args,'protocol',None) and args.protocol.lower()!=r['protocol'].lower():
            continue
        if getattr(args,'port',None) is not None and args.port not in (r['local']['port'],r['remote']['port']):
            continue
        if getattr(args,'address',None) and args.address not in (r['local']['address'],r['remote']['address']):
            continue
        if getattr(args,'match',None) and args.match.lower() not in r['raw'].lower():
            continue
        filtered.append(r)
    return filtered


def socket_key(r):
    return '|'.join([str(r['protocol']),str(r['local']['raw']),str(r['remote']['raw']),str(r['state'])])


def socket_flow_key(r):
    return '|'.join([str(r['protocol']),str(r['local']['raw']),str(r['remote']['raw'])])


def summarize_connections(rows):
    states=collections.Counter(r['state'] for r in rows)
    protocols=collections.Counter(r['protocol'] for r in rows)
    local_ports=collections.Counter(str(r['local']['port']) for r in rows if r['local']['port'] is not None)
    remote_ports=collections.Counter(str(r['remote']['port']) for r in rows if r['remote']['port'] is not None)
    peers=collections.Counter(r['remote']['address'] for r in rows)
    send=[r['send_q'] for r in rows if isinstance(r['send_q'],(int,float))]
    recv=[r['recv_q'] for r in rows if isinstance(r['recv_q'],(int,float))]
    return {'total':len(rows),'states':dict(states),'protocols':dict(protocols),'top_local_ports':local_ports.most_common(25),'top_remote_ports':remote_ports.most_common(25),'top_peers':peers.most_common(25),'send_queue':quantiles(send),'recv_queue':quantiles(recv),'state_entropy':entropy(states.elements()),'unique_flows':len(set(map(socket_flow_key,rows)))}


def diff_connections(before,after):
    a=collections.Counter(socket_key(r) for r in before)
    b=collections.Counter(socket_key(r) for r in after)
    return {'opened':list((b-a).elements()),'closed':list((a-b).elements()),'opened_count':sum((b-a).values()),'closed_count':sum((a-b).values()),'before_count':len(before),'after_count':len(after)}


def compare_counters(before,after,seconds):
    index_a={(x['section'],x['label']):x['value'] for x in before}
    index_b={(x['section'],x['label']):x['value'] for x in after}
    rows=[]
    for key in sorted(set(index_a)|set(index_b)):
        x=index_a.get(key)
        y=index_b.get(key)
        d=delta(y,x)
        rows.append({'section':key[0],'label':key[1],'before':x,'after':y,'delta':d,'rate_per_second':rate(y,x,seconds),'counter_reset':d is not None and d<0})
    return rows


def interesting_stats(entries,pattern=None):
    if pattern:
        return [x for x in entries if pattern.lower() in x['label'].lower()]
    return [x for x in entries if any(w in x['label'].lower() for w in COUNTER_WORDS)]


def categorize_stat(label):
    l=label.lower()
    for category,terms in STAT_CATEGORIES.items():
        if any(t in l for t in terms):
            return category
    return 'other'


def categorize_stats(entries):
    grouped=collections.defaultdict(list)
    for entry in entries:
        grouped[categorize_stat(entry['label'])].append(entry)
    return dict(grouped)


def score_connection(r):
    score=0
    reasons=[]
    if r['state']=='CLOSE_WAIT':
        score+=3
        reasons.append('close_wait_connection')
    if r['state']=='SYN_SENT':
        score+=2
        reasons.append('outbound_handshake_pending')
    if r['state']=='SYN_RECEIVED':
        score+=2
        reasons.append('inbound_handshake_pending')
    if isinstance(r['send_q'],int) and r['send_q']>262144:
        score+=3
        reasons.append('large_send_queue')
    if isinstance(r['recv_q'],int) and r['recv_q']>262144:
        score+=3
        reasons.append('large_receive_queue')
    if r['remote']['wildcard'] and r['state']=='ESTABLISHED':
        score+=1
        reasons.append('unexpected_wildcard_peer')
    return {'score':score,'reasons':reasons}


def anomalies(rows):
    found=[]
    for r in rows:
        s=score_connection(r)
        if s['score']:
            found.append({'flow':socket_flow_key(r),'state':r['state'],**s})
    return sorted(found,key=lambda x:(-x['score'],x['flow']))


def snapshot(timeout=8,include_processes=True,include_interfaces=True,include_routes=True,include_sysctl=True):
    commands={'connections':['netstat','-an','-p','tcp'],'tcp_stats':['netstat','-s','-p','tcp'],'sockstat':['sockstat','-4','-6','-P','tcp'],'interfaces':['ifconfig','-a'],'routes':['netstat','-rn'],'vmstat':['vmstat','-c','1'],'uname':['uname','-a'],'sysctl':['sysctl','-a']}
    if not include_processes:
        commands.pop('sockstat')
    if not include_interfaces:
        commands.pop('interfaces')
    if not include_routes:
        commands.pop('routes')
    if not include_sysctl:
        commands.pop('sysctl')
    results={key:run(argv,timeout) for key,argv in commands.items()}
    get=lambda k:results[k].stdout if k in results and results[k].returncode==0 else ''
    conns=parse_netstat_connections(get('connections'))
    stats=parse_netstat_stats(get('tcp_stats'))
    data={'schema':SCHEMA,'version':VERSION,'timestamp':now(),'host':socket.gethostname(),'platform':platform.platform(),'commands':{k:v.as_dict() for k,v in results.items()},'connections':conns,'tcp_stats':stats,'summary':summarize_connections(conns),'anomalies':anomalies(conns),'uname':get('uname').strip()}
    if 'sockstat' in results:
        data['process_sockets']=parse_sockstat(get('sockstat'))
    if 'interfaces' in results:
        data['interfaces']=parse_interfaces(get('interfaces'))
    if 'routes' in results:
        data['routes']=parse_routes(get('routes'))
    if 'sysctl' in results:
        all_sysctls=parse_sysctl(get('sysctl'))
        data['sysctl']={k:v for k,v in all_sysctls.items() if k.startswith(('net.inet.tcp.','net.inet.ip.','net.inet6.ip6.','kern.ipc.','net.link.'))}
    return data


def snapshot_diff(a,b):
    seconds=max(0,(datetime.datetime.fromisoformat(b['timestamp'])-datetime.datetime.fromisoformat(a['timestamp'])).total_seconds())
    sa=a.get('sysctl',{})
    sb=b.get('sysctl',{})
    changed={k:{'before':sa.get(k),'after':sb.get(k)} for k in sorted(set(sa)|set(sb)) if sa.get(k)!=sb.get(k)}
    return {'schema':SCHEMA,'before':a.get('timestamp'),'after':b.get('timestamp'),'seconds':seconds,'connections':diff_connections(a.get('connections',[]),b.get('connections',[])),'tcp_counters':compare_counters(a.get('tcp_stats',[]),b.get('tcp_stats',[]),seconds),'sysctl_changes':changed,'summary_before':a.get('summary',{}),'summary_after':b.get('summary',{})}


def format_value(value):
    if value is None:
        return '-'
    if isinstance(value,float):
        return f'{value:.4f}'
    return str(value)


def print_table(rows,columns,max_rows=100):
    if not rows:
        print('No rows')
        return
    rows=rows[:max_rows]
    widths={k:min(64,max(len(label),*(len(format_value(row.get(k))) for row in rows))) for k,label in columns}
    print('  '.join(label.ljust(widths[k]) for k,label in columns))
    print('  '.join('-'*widths[k] for k,_ in columns))
    for row in rows:
        print('  '.join(format_value(row.get(k))[:widths[k]].ljust(widths[k]) for k,_ in columns))


def print_summary(s):
    print('TCP connections:',s.get('total',0))
    print('Unique flows:',s.get('unique_flows',0))
    print('State entropy:',s.get('state_entropy',0))
    print('States:')
    for k,v in sorted(s.get('states',{}).items(),key=lambda x:(-x[1],x[0])):
        print(f'  {k:<18} {v}')
    print('Top peers:')
    for peer,count in s.get('top_peers',[])[:10]:
        print(f'  {peer:<40} {count}')


def command_doctor(args):
    checks=[]
    for exe in ('netstat','sockstat','sysctl','ifconfig','vmstat','uname','route','ps','procstat','pkg','freebsd-version'):
        path=shutil.which(exe)
        checks.append({'tool':exe,'path':path,'available':bool(path)})
    out={'timestamp':now(),'version':VERSION,'python':sys.version,'platform':platform.platform(),'freebsd':sys.platform.startswith('freebsd'),'tools':checks,'network_activity':'none','privileges':'read-only'}
    if args.json:
        write_json(args.output,out)
    else:
        print('TCP Forensics BSD',VERSION)
        print('Platform:',out['platform'])
        print('Python:',sys.version.split()[0])
        print_table(checks,[('tool','TOOL'),('available','AVAILABLE'),('path','PATH')])
        if not out['freebsd']:
            print('Warning: intended for FreeBSD; parser self-tests are portable')
    return 0


def command_snapshot(args):
    s=snapshot(args.timeout,not args.no_processes,not args.no_interfaces,not args.no_routes,not args.no_sysctl)
    if args.output or args.json:
        write_json(args.output,s)
    else:
        print('Snapshot:',s['timestamp'])
        print('Host:',s['host'])
        print('Kernel:',s['uname'])
        print_summary(s['summary'])
        print('Anomalies:',len(s['anomalies']))
        for k,v in s['commands'].items():
            if v['returncode']!=0:
                print('Warning:',k,v['stderr'][:160])
    return 0


def command_sockets(args):
    s=snapshot(args.timeout,False,False,False,False)
    rows=filter_connections(s['connections'],args)
    if args.json:
        write_json(args.output,{'timestamp':s['timestamp'],'connections':rows,'summary':summarize_connections(rows)})
    else:
        print_table([{'proto':r['protocol'],'local':r['local']['raw'],'remote':r['remote']['raw'],'state':r['state'],'recv':r['recv_q'],'send':r['send_q']} for r in rows],[('proto','PROTO'),('local','LOCAL'),('remote','REMOTE'),('state','STATE'),('recv','RECV-Q'),('send','SEND-Q')],args.limit)
        print_summary(summarize_connections(rows))
    return 0


def command_stats(args):
    r=run(['netstat','-s','-p','tcp'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'netstat failed')
    entries=interesting_stats(parse_netstat_stats(r.stdout),args.match)
    if args.category:
        entries=[x for x in entries if categorize_stat(x['label'])==args.category]
    if args.json:
        write_json(args.output,{'timestamp':now(),'entries':entries,'categories':{k:len(v) for k,v in categorize_stats(entries).items()}})
    else:
        print_table([{'section':x['section'],'value':x['value'],'label':x['label'],'category':categorize_stat(x['label'])} for x in entries],[('value','COUNT'),('category','CATEGORY'),('label','DESCRIPTION')],args.limit)
    return 0


def command_sysctl(args):
    keys=args.keys or ['net.inet.tcp']
    all_values={}
    errors=[]
    for key in keys:
        prefix=key.rstrip('.')
        r=run(['sysctl','-a'] if prefix in ('net.inet.tcp','net.inet.ip','net.inet6.ip6') else ['sysctl',key],args.timeout)
        if r.returncode:
            errors.append({'key':key,'error':r.stderr.strip()})
        else:
            values=parse_sysctl(r.stdout)
            all_values.update({k:v for k,v in values.items() if k.startswith(prefix+'.')} if prefix in ('net.inet.tcp','net.inet.ip','net.inet6.ip6') else values)
    if args.match:
        all_values={k:v for k,v in all_values.items() if args.match.lower() in k.lower()}
    if args.json:
        write_json(args.output,{'timestamp':now(),'values':all_values,'errors':errors})
    else:
        print_table([{'name':k,'value':v} for k,v in sorted(all_values.items())],[('name','SYSCTL'),('value','VALUE')],args.limit)
        for e in errors:
            print('Warning:',e['key'],e['error'])
    return 0


def command_processes(args):
    r=run(['sockstat','-4','-6','-P','tcp'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'sockstat failed')
    rows=parse_sockstat(r.stdout)
    if args.pid is not None:
        rows=[x for x in rows if x['pid']==args.pid]
    if args.match:
        rows=[x for x in rows if args.match.lower() in x['raw'].lower()]
    if args.json:
        write_json(args.output,{'timestamp':now(),'process_sockets':rows})
    else:
        print_table([{'user':x['user'],'pid':x['pid'],'command':x['command'],'fd':x['fd'],'proto':x['protocol'],'local':x['local']['raw'],'remote':x['remote']['raw']} for x in rows],[('user','USER'),('pid','PID'),('command','COMMAND'),('fd','FD'),('proto','PROTO'),('local','LOCAL'),('remote','REMOTE')],args.limit)
    return 0


def command_routes(args):
    r=run(['netstat','-rn'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'netstat failed')
    rows=parse_routes(r.stdout)
    if args.family:
        rows=[x for x in rows if x['family']==args.family]
    if args.json:
        write_json(args.output,{'timestamp':now(),'routes':rows})
    else:
        print_table(rows,[('family','FAMILY'),('destination','DESTINATION'),('gateway','GATEWAY'),('flags','FLAGS'),('interface','INTERFACE')],args.limit)
    return 0


def command_interfaces(args):
    r=run(['ifconfig','-a'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'ifconfig failed')
    rows=parse_interfaces(r.stdout)
    if args.json:
        write_json(args.output,{'timestamp':now(),'interfaces':rows})
    else:
        for x in rows:
            print(x['name'],','.join(x['flags']))
            for a in x['addresses']:
                print(' ',a['family'],a['address'])
    return 0


def command_diff(args):
    a=read_json(args.before)
    b=read_json(args.after)
    result=snapshot_diff(a,b)
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Elapsed seconds:',result['seconds'])
        c=result['connections']
        print('Opened:',c['opened_count'],'Closed:',c['closed_count'])
        print('Sysctl changes:',len(result['sysctl_changes']))
        changes=[x for x in result['tcp_counters'] if x['delta'] is not None and x['delta']!=0]
        print_table(changes,[('delta','DELTA'),('rate_per_second','RATE/S'),('label','COUNTER')],args.limit)
    return 0


def command_report(args):
    s=read_json(args.file)
    if s.get('schema')!=SCHEMA:
        raise ForensicsError('unsupported snapshot schema')
    rows=filter_connections(s.get('connections',[]),args)
    report={'timestamp':now(),'source':args.file,'captured_at':s.get('timestamp'),'host':s.get('host'),'summary':summarize_connections(rows),'anomalies':anomalies(rows),'tcp_stats_by_category':{k:len(v) for k,v in categorize_stats(s.get('tcp_stats',[])).items()},'interfaces':len(s.get('interfaces',[])),'routes':len(s.get('routes',[])),'sysctl_count':len(s.get('sysctl',{}))}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Host:',report['host'])
        print('Captured:',report['captured_at'])
        print_summary(report['summary'])
        print('Anomalies:',len(report['anomalies']))
        print_table(report['anomalies'],[('score','SCORE'),('state','STATE'),('flow','FLOW')],args.limit)
    return 0


def command_watch(args):
    started=time.monotonic()
    previous=None
    samples=0
    path=args.jsonl
    if path:
        pathlib.Path(path).expanduser().parent.mkdir(parents=True,exist_ok=True)
    try:
        while True:
            sample=snapshot(args.timeout,False,False,False,False)
            samples+=1
            record={'schema':SCHEMA,'kind':'sample','timestamp':sample['timestamp'],'sample':samples,'summary':sample['summary'],'anomalies':sample['anomalies'][:args.max_anomalies]}
            if previous is not None:
                seconds=max(.000001,(datetime.datetime.fromisoformat(sample['timestamp'])-datetime.datetime.fromisoformat(previous['timestamp'])).total_seconds())
                record['connection_delta']=diff_connections(previous['connections'],sample['connections'])
                record['counter_delta']=[x for x in compare_counters(previous['tcp_stats'],sample['tcp_stats'],seconds) if x['delta'] is not None and x['delta']!=0]
            if path:
                append_jsonl(path,record)
            if args.json:
                print(json.dumps(record,sort_keys=True),flush=True)
            else:
                summary=sample['summary']
                print(f"{record['timestamp']} sample={samples} connections={summary['total']} established={summary['states'].get('ESTABLISHED',0)} close_wait={summary['states'].get('CLOSE_WAIT',0)} anomalies={len(sample['anomalies'])}",flush=True)
                if 'connection_delta' in record:
                    print('  opened:',record['connection_delta']['opened_count'],'closed:',record['connection_delta']['closed_count'],flush=True)
            previous=sample
            if args.count and samples>=args.count:
                break
            if args.duration and time.monotonic()-started>=args.duration:
                break
            time.sleep(max(.05,args.interval))
    except KeyboardInterrupt:
        pass
    return 0


def command_timeline(args):
    events=[]
    with open(args.file,encoding='utf-8') as f:
        for number,line in enumerate(f,1):
            if not line.strip():
                continue
            try:
                item=json.loads(line)
            except json.JSONDecodeError:
                if args.strict:
                    raise ForensicsError(f'invalid JSON on line {number}')
                continue
            if item.get('kind')=='sample':
                events.append(item)
    counts=[e.get('summary',{}).get('total',0) for e in events]
    established=[e.get('summary',{}).get('states',{}).get('ESTABLISHED',0) for e in events]
    anomalies_counts=[len(e.get('anomalies',[])) for e in events]
    report={'schema':SCHEMA,'samples':len(events),'first':events[0]['timestamp'] if events else None,'last':events[-1]['timestamp'] if events else None,'connections':quantiles(counts),'established':quantiles(established),'anomalies':quantiles(anomalies_counts),'peak_connections':max(counts,default=0),'peak_anomalies':max(anomalies_counts,default=0)}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print(json.dumps(report,indent=2))
    return 0


def command_export(args):
    data=read_json(args.file)
    section=args.section
    rows=data.get(section)
    if not isinstance(rows,list):
        raise ForensicsError(f'section {section!r} is not a list')
    flat=[]
    def flatten(obj,prefix=''):
        result={}
        for key,value in obj.items():
            name=prefix+key
            if isinstance(value,dict):
                result.update(flatten(value,name+'.'))
            elif isinstance(value,list):
                result[name]=json.dumps(value)
            else:
                result[name]=value
        return result
    for row in rows:
        flat.append(flatten(row) if isinstance(row,dict) else {'value':row})
    keys=sorted(set().union(*(r.keys() for r in flat))) if flat else ['value']
    if args.output:
        with open(args.output,'w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=keys)
            writer.writeheader()
            writer.writerows(flat)
    else:
        writer=csv.DictWriter(sys.stdout,fieldnames=keys)
        writer.writeheader()
        writer.writerows(flat)
    return 0


def command_selftest(args):
    tests=[]
    def check(name,fn):
        try:
            fn()
            tests.append({'test':name,'passed':True})
        except Exception as e:
            tests.append({'test':name,'passed':False,'error':str(e)})
    def eq(a,b):
        if a!=b:
            raise AssertionError(f'{a!r} != {b!r}')
    check('number',lambda:eq(safe_number('1,024'),1024))
    check('endpoint_ipv4',lambda:eq(parse_endpoint('127.0.0.1.443')['port'],443))
    check('endpoint_ipv6',lambda:eq(parse_endpoint('::1.443')['port'],443))
    check('state',lambda:eq(normalize_state('FIN_WAIT1'),'FIN_WAIT_1'))
    check('entropy',lambda:eq(entropy([]),0.0))
    check('quantile',lambda:eq(quantiles([1,2,3])['median'],2))
    check('stats',lambda:eq(parse_netstat_stats('tcp:\n  123 packets sent\n')[0]['value'],123))
    check('sysctl',lambda:eq(parse_sysctl('net.inet.tcp.rfc1323: 1')['net.inet.tcp.rfc1323'],1))
    check('sockstat',lambda:eq(len(parse_sockstat('USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\nroot sshd 123 4 tcp4 *:22 *:*')),1))
    check('diff',lambda:eq(diff_connections([],[])['opened_count'],0))
    check('rate',lambda:eq(rate(15,10,5),1.0))
    check('categorization',lambda:eq(isinstance(categorize_stat('retransmitted packets'),str),True))
    check('summary',lambda:eq(summarize_connections([])['total'],0))
    check('anomalies',lambda:eq(anomalies([]),[]))
    check('schema',lambda:eq(SCHEMA,'tcp-forensics-bsd/v1'))
    passed=sum(x['passed'] for x in tests)
    if args.json:
        write_json(args.output,{'passed':passed,'total':len(tests),'tests':tests})
    else:
        for t in tests:
            print(('PASS' if t['passed'] else 'FAIL'),t['test'],t.get('error',''))
        print(f'{passed}/{len(tests)} passed')
    return 0 if passed==len(tests) else 1

STAT_CATEGORIES={
    'retransmission':('retrans','re-send','resent','rexmit'),
    'loss':('drop','lost','discard','loss'),
    'timeout':('timeout','timed out','time wait'),
    'handshake':('syn','connection request','listen queue','accept'),
    'termination':('fin','reset','rst','closed','close'),
    'congestion':('congestion','cwnd','slow start','fast recovery'),
    'acknowledgment':('ack','acknowledg'),
    'window':('window','zero win','persist'),
    'data':('byte','packet','segment','received','sent'),
    'security':('invalid','bad','challenge','spoof','attack','blackhole'),
    'offload':('tso','lro','offload','checksum'),
    'reordering':('reorder','duplicate','out of order'),
    'keepalive':('keepalive','keep alive'),
    'memory':('buffer','socket','allocation','memory'),
}


def parse_numeric_suffix(text):
    value=str(text).strip().lower()
    match=re.fullmatch(r'([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([kmgt]?)(?:i?b)?',value)
    if not match:
        return safe_number(text)
    number=float(match.group(1))
    multipliers={'':1,'k':1024,'m':1024**2,'g':1024**3,'t':1024**4}
    result=number*multipliers[match.group(2)]
    return int(result) if result.is_integer() else result


def is_private_address(value):
    try:
        return ipaddress.ip_address(value.split('%')[0]).is_private
    except ValueError:
        return False


def is_loopback_address(value):
    try:
        return ipaddress.ip_address(value.split('%')[0]).is_loopback
    except ValueError:
        return False


def is_global_address(value):
    try:
        return ipaddress.ip_address(value.split('%')[0]).is_global
    except ValueError:
        return False


def address_class(value):
    if value in ('*','0.0.0.0','::'):
        return 'wildcard'
    try:
        ip=ipaddress.ip_address(value.split('%')[0])
    except ValueError:
        return 'hostname_or_unknown'
    if ip.is_loopback:
        return 'loopback'
    if ip.is_link_local:
        return 'link_local'
    if ip.is_multicast:
        return 'multicast'
    if ip.is_private:
        return 'private'
    if ip.is_global:
        return 'global'
    return 'special'


def endpoint_identity(endpoint):
    return f"{endpoint.get('address')}:{endpoint.get('port')}"


def connection_identity(row,ignore_state=False):
    keys=[row.get('protocol',''),endpoint_identity(row.get('local',{})),endpoint_identity(row.get('remote',{}))]
    if not ignore_state:
        keys.append(row.get('state',''))
    return tuple(keys)


def group_by(rows,key):
    out=collections.defaultdict(list)
    for row in rows:
        out[key(row)].append(row)
    return dict(out)


def count_by(rows,key):
    return dict(collections.Counter(key(row) for row in rows))


def tcp_flow_statistics(rows):
    peers=collections.Counter()
    local=collections.Counter()
    remote=collections.Counter()
    state_by_peer=collections.defaultdict(collections.Counter)
    for row in rows:
        peer=row['remote']['address']
        peers[peer]+=1
        local[row['local']['port']]+=1
        remote[row['remote']['port']]+=1
        state_by_peer[peer][row['state']]+=1
    return {'peer_counts':dict(peers),'local_port_counts':{str(k):v for k,v in local.items()},'remote_port_counts':{str(k):v for k,v in remote.items()},'peer_states':{k:dict(v) for k,v in state_by_peer.items()},'unique_peers':len(peers),'unique_local_ports':len(local),'unique_remote_ports':len(remote)}


def connection_risk_indicators(rows):
    findings=[]
    for row in rows:
        local=row['local']
        remote=row['remote']
        if row['state']=='LISTEN' and local['wildcard']:
            findings.append({'kind':'wildcard_listener','severity':'informational','flow':socket_flow_key(row),'details':'Listening socket bound to all addresses'})
        if row['state']=='ESTABLISHED' and is_global_address(remote['address']):
            findings.append({'kind':'external_peer','severity':'informational','flow':socket_flow_key(row),'details':'Established connection with globally routable peer'})
        if row['state']=='CLOSE_WAIT':
            findings.append({'kind':'close_wait','severity':'low','flow':socket_flow_key(row),'details':'Peer closed connection; local application has not yet closed its endpoint'})
        if row['state']=='SYN_SENT':
            findings.append({'kind':'pending_connect','severity':'informational','flow':socket_flow_key(row),'details':'Outbound TCP handshake is pending at capture time'})
        if row['state']=='SYN_RECEIVED':
            findings.append({'kind':'pending_accept','severity':'informational','flow':socket_flow_key(row),'details':'Inbound TCP handshake is pending at capture time'})
    return findings


def tcp_state_transitions(before,after):
    a=group_by(before,lambda r:connection_identity(r,True))
    b=group_by(after,lambda r:connection_identity(r,True))
    transitions=[]
    for key in sorted(set(a)&set(b)):
        from_states=collections.Counter(x['state'] for x in a[key])
        to_states=collections.Counter(x['state'] for x in b[key])
        if from_states!=to_states:
            transitions.append({'flow':list(key),'before':dict(from_states),'after':dict(to_states)})
    return transitions


def top_n(counter,n=20):
    return [{'name':str(key),'count':count} for key,count in collections.Counter(counter).most_common(n)]


def histogram(values,buckets=10):
    values=[float(x) for x in values if isinstance(x,(int,float)) and math.isfinite(x)]
    if not values:
        return []
    low=min(values)
    high=max(values)
    if low==high:
        return [{'low':low,'high':high,'count':len(values)}]
    width=(high-low)/buckets
    counts=[0]*buckets
    for value in values:
        idx=min(buckets-1,int((value-low)/width))
        counts[idx]+=1
    return [{'low':round(low+i*width,5),'high':round(low+(i+1)*width,5),'count':counts[i]} for i in range(buckets)]


def moving_average(values,window=5):
    out=[]
    q=collections.deque()
    total=0.0
    for value in values:
        v=float(value)
        q.append(v)
        total+=v
        if len(q)>window:
            total-=q.popleft()
        out.append(round(total/len(q),5))
    return out


def exponential_average(values,alpha=.3):
    result=[]
    average=None
    for value in values:
        v=float(value)
        average=v if average is None else alpha*v+(1-alpha)*average
        result.append(round(average,5))
    return result


def robust_zscores(values):
    values=list(values)
    if not values:
        return []
    median=statistics.median(values)
    mad=statistics.median(abs(x-median) for x in values)
    if mad==0:
        return [0.0 if x==median else (10.0 if x>median else -10.0) for x in values]
    return [round(.6745*(x-median)/mad,5) for x in values]


def detect_spikes(values,threshold=3.5):
    z=robust_zscores(values)
    return [{'index':i,'value':values[i],'score':score} for i,score in enumerate(z) if abs(score)>=threshold]


def series_differences(values):
    return [values[i]-values[i-1] for i in range(1,len(values))]


def safe_div(numerator,denominator):
    return numerator/denominator if denominator else None


def jain_fairness(values):
    values=[float(x) for x in values]
    if not values or not sum(x*x for x in values):
        return None
    return round(sum(values)**2/(len(values)*sum(x*x for x in values)),6)


def gini(values):
    values=sorted(max(0,float(x)) for x in values)
    n=len(values)
    total=sum(values)
    if not n or not total:
        return 0.0
    return round(sum((2*i-n-1)*v for i,v in enumerate(values,1))/(n*total),6)


def herfindahl(values):
    total=sum(values)
    if not total:
        return 0.0
    return round(sum((x/total)**2 for x in values),6)


def peer_concentration(rows):
    c=collections.Counter(row['remote']['address'] for row in rows)
    values=list(c.values())
    return {'peers':len(c),'gini':gini(values),'herfindahl':herfindahl(values),'fairness':jain_fairness(values),'top':top_n(c)}


def sysctl_classification(name):
    key=name.lower()
    if 'blackhole' in key or 'drop' in key or 'challenge' in key:
        return 'security'
    if 'sack' in key or 'rfc1323' in key or 'ecn' in key:
        return 'protocol_features'
    if 'keep' in key or 'timewait' in key or 'msl' in key:
        return 'connection_lifecycle'
    if 'send' in key or 'recv' in key or 'buffer' in key:
        return 'buffering'
    if 'cong' in key or 'cubic' in key or 'newreno' in key:
        return 'congestion_control'
    if 'reass' in key or 'retrans' in key or 'rexmit' in key:
        return 'retransmission'
    if 'tso' in key or 'offload' in key:
        return 'offload'
    return 'other'


def sysctl_inventory(values):
    result=collections.defaultdict(list)
    for key,value in sorted(values.items()):
        result[sysctl_classification(key)].append({'name':key,'value':value})
    return dict(result)


def parse_tcp_cc(text):
    return parse_sysctl(text)


def snapshot_fingerprint(s,include_connections=False):
    data={'sysctl':s.get('sysctl',{}),'interfaces':s.get('interfaces',[]),'routes':s.get('routes',[]),'uname':s.get('uname','')}
    if include_connections:
        data['connections']=s.get('connections',[])
    canonical=json.dumps(data,sort_keys=True,separators=(',',':'),default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_snapshot(s):
    findings=[]
    if not isinstance(s,dict):
        return {'valid':False,'findings':['root must be object']}
    if s.get('schema')!=SCHEMA:
        findings.append('schema does not match')
    if not isinstance(s.get('connections'),list):
        findings.append('connections must be list')
    if not isinstance(s.get('tcp_stats'),list):
        findings.append('tcp_stats must be list')
    if not isinstance(s.get('timestamp'),str):
        findings.append('timestamp must be string')
    try:
        datetime.datetime.fromisoformat(s.get('timestamp',''))
    except (ValueError,TypeError):
        findings.append('timestamp is not ISO 8601')
    for index,row in enumerate(s.get('connections',[]) if isinstance(s.get('connections'),list) else []):
        if not isinstance(row,dict):
            findings.append(f'connection {index} must be object')
        elif row.get('state') not in TCP_STATES:
            findings.append(f'connection {index} has unrecognized state')
        if len(findings)>50:
            break
    return {'valid':not findings,'findings':findings,'connection_count':len(s.get('connections',[])) if isinstance(s.get('connections'),list) else None}


def process_socket_correlation(connections,process_sockets):
    by_local=collections.defaultdict(list)
    for proc in process_sockets:
        by_local[(proc['local']['address'],proc['local']['port'])].append(proc)
    output=[]
    for row in connections:
        endpoint=row['local']
        candidates=by_local.get((endpoint['address'],endpoint['port']),[])
        if not candidates and endpoint['address'] not in ('*','0.0.0.0','::'):
            candidates=by_local.get(('*',endpoint['port']),[])
        output.append({'flow':socket_flow_key(row),'state':row['state'],'processes':[{'pid':p['pid'],'command':p['command'],'user':p['user'],'fd':p['fd']} for p in candidates],'matched':bool(candidates)})
    return output


def listener_inventory(connections,process_sockets):
    matches=process_socket_correlation(connections,process_sockets)
    result=[]
    for row,match in zip(connections,matches):
        if row['state']!='LISTEN':
            continue
        result.append({'protocol':row['protocol'],'address':row['local']['address'],'port':row['local']['port'],'scope':address_class(row['local']['address']),'processes':match['processes'],'process_match':match['matched']})
    return sorted(result,key=lambda x:(str(x['port']),x['address']))


def connection_matrix(rows):
    result=collections.defaultdict(collections.Counter)
    for row in rows:
        result[row['local']['address']][row['remote']['address']]+=1
    return {local:dict(peers) for local,peers in result.items()}


def state_matrix(rows):
    result=collections.defaultdict(collections.Counter)
    for row in rows:
        result[row['protocol']][row['state']]+=1
    return {proto:dict(states) for proto,states in result.items()}


def queue_pressure(rows,threshold=65536):
    findings=[]
    for row in rows:
        send=row.get('send_q')
        recv=row.get('recv_q')
        if isinstance(send,(int,float)) and send>=threshold:
            findings.append({'flow':socket_flow_key(row),'kind':'send','bytes':send,'threshold':threshold})
        if isinstance(recv,(int,float)) and recv>=threshold:
            findings.append({'flow':socket_flow_key(row),'kind':'receive','bytes':recv,'threshold':threshold})
    return sorted(findings,key=lambda x:-x['bytes'])


def endpoint_port_analysis(rows):
    result=collections.defaultdict(lambda:{'states':collections.Counter(),'peers':set(),'connections':0})
    for row in rows:
        port=row['local']['port']
        if port is None:
            continue
        entry=result[port]
        entry['states'][row['state']]+=1
        entry['peers'].add(row['remote']['address'])
        entry['connections']+=1
    return [{'port':port,'connections':x['connections'],'peers':len(x['peers']),'states':dict(x['states'])} for port,x in sorted(result.items(),key=lambda x:-x[1]['connections'])]


def summarize_tcp_stats(entries):
    categories=categorize_stats(entries)
    return {'entries':len(entries),'categories':{k:len(v) for k,v in categories.items()},'nonzero':sum(x['value']!=0 for x in entries),'zeros':sum(x['value']==0 for x in entries),'largest':sorted(entries,key=lambda x:-x['value'])[:20]}


def classify_counter_deltas(rows):
    groups=collections.defaultdict(list)
    for row in rows:
        groups[categorize_stat(row['label'])].append(row)
    return {name:{'count':len(items),'increasing':sum((x['delta'] or 0)>0 for x in items),'decreasing':sum((x['delta'] or 0)<0 for x in items),'top':sorted(items,key=lambda x:-(x['delta'] or 0))[:10]} for name,items in groups.items()}


def audit_snapshot(s):
    rows=s.get('connections',[])
    stats=s.get('tcp_stats',[])
    sysctls=s.get('sysctl',{})
    findings=connection_risk_indicators(rows)
    for key,value in sysctls.items():
        if key.endswith('.blackhole') and value==0:
            findings.append({'kind':'blackhole_disabled','severity':'informational','key':key,'details':'TCP blackhole option is disabled; this is not necessarily a vulnerability'})
        if key.endswith('.log_in_vain') and value==0:
            findings.append({'kind':'log_in_vain_disabled','severity':'informational','key':key,'details':'TCP connection attempt logging is disabled'})
    return {'timestamp':now(),'host':s.get('host'),'findings':findings,'counts':dict(collections.Counter(x['kind'] for x in findings)),'interpretation':'Heuristic observations, not proof of compromise or vulnerability','stats':summarize_tcp_stats(stats)}


def command_audit(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,True)
    report=audit_snapshot(s)
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Host:',report['host'])
        print('Findings:',len(report['findings']))
        print('These findings are heuristic, not vulnerability verdicts')
        print_table(report['findings'],[('severity','SEVERITY'),('kind','KIND'),('flow','FLOW'),('details','DETAILS')],args.limit)
    return 0


def command_listeners(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,False)
    rows=listener_inventory(s.get('connections',[]),s.get('process_sockets',[]))
    if args.port is not None:
        rows=[r for r in rows if r['port']==args.port]
    if args.scope:
        rows=[r for r in rows if r['scope']==args.scope]
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'listeners':rows})
    else:
        print_table([{'proto':r['protocol'],'address':r['address'],'port':r['port'],'scope':r['scope'],'processes':','.join(str(p['pid'])+':'+p['command'] for p in r['processes'])} for r in rows],[('proto','PROTO'),('address','ADDRESS'),('port','PORT'),('scope','SCOPE'),('processes','PROCESS')],args.limit)
    return 0


def command_queues(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    rows=queue_pressure(s.get('connections',[]),args.threshold)
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'threshold':args.threshold,'queues':rows})
    else:
        print_table(rows,[('kind','QUEUE'),('bytes','BYTES'),('threshold','THRESHOLD'),('flow','FLOW')],args.limit)
    return 0


def command_peers(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    rows=filter_connections(s.get('connections',[]),args)
    report=peer_concentration(rows)
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Peers:',report['peers'])
        print('Gini:',report['gini'])
        print('Herfindahl:',report['herfindahl'])
        print('Jain fairness:',report['fairness'])
        print_table(report['top'],[('name','PEER'),('count','CONNECTIONS')],args.limit)
    return 0


def command_matrix(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    rows=filter_connections(s.get('connections',[]),args)
    matrix=state_matrix(rows) if args.type=='state' else connection_matrix(rows)
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'type':args.type,'matrix':matrix})
    else:
        for source,targets in sorted(matrix.items()):
            print(source)
            for target,count in sorted(targets.items(),key=lambda x:-x[1])[:args.limit]:
                print(f'  {target:<44} {count}')
    return 0


def command_fingerprint(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,True,True,True)
    digest=snapshot_fingerprint(s,args.include_connections)
    report={'host':s.get('host'),'timestamp':s.get('timestamp'),'sha256':digest,'includes_connections':args.include_connections}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print(json.dumps(report,indent=2))
    return 0


def command_verify(args):
    s=read_json(args.file)
    report=verify_snapshot(s)
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Valid:',report['valid'])
        print('Connections:',report.get('connection_count'))
        for finding in report['findings']:
            print('Issue:',finding)
    return 0 if report['valid'] else 1


def command_inventory(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,True,True,True)
    rows=s.get('connections',[])
    report={'timestamp':s.get('timestamp'),'host':s.get('host'),'kernel':s.get('uname'),'connections':summarize_connections(rows),'listeners':listener_inventory(rows,s.get('process_sockets',[])),'peers':peer_concentration(rows),'ports':endpoint_port_analysis(rows),'states_by_protocol':state_matrix(rows),'sysctl_categories':{k:len(v) for k,v in sysctl_inventory(s.get('sysctl',{})).items()},'tcp_stats':summarize_tcp_stats(s.get('tcp_stats',[])),'interfaces':s.get('interfaces',[]),'routes':s.get('routes',[]),'fingerprint':snapshot_fingerprint(s)}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Host:',report['host'])
        print('Kernel:',report['kernel'])
        print('Fingerprint:',report['fingerprint'])
        print_summary(report['connections'])
        print('Listeners:',len(report['listeners']))
        print('Interfaces:',len(report['interfaces']))
        print('Routes:',len(report['routes']))
    return 0


def command_analyze(args):
    s=read_json(args.file)
    rows=filter_connections(s.get('connections',[]),args)
    report={'schema':SCHEMA,'timestamp':now(),'source':args.file,'connection_summary':summarize_connections(rows),'risk_indicators':connection_risk_indicators(rows),'queue_pressure':queue_pressure(rows,args.queue_threshold),'peer_concentration':peer_concentration(rows),'flow_statistics':tcp_flow_statistics(rows),'port_statistics':endpoint_port_analysis(rows),'protocol_state_matrix':state_matrix(rows),'tcp_stats_summary':summarize_tcp_stats(s.get('tcp_stats',[])),'sysctl_inventory':sysctl_inventory(s.get('sysctl',{}))}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Analysis:',args.file)
        print_summary(report['connection_summary'])
        print('Risk indicators:',len(report['risk_indicators']))
        print('Queue pressure findings:',len(report['queue_pressure']))
        print('Unique peers:',report['peer_concentration']['peers'])
        print('TCP statistics:',report['tcp_stats_summary']['entries'])
    return 0


def command_countertrend(args):
    records=[]
    with open(args.file,encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                record=json.loads(line)
            except json.JSONDecodeError:
                if args.strict:
                    raise
                continue
            if record.get('kind')=='sample':
                records.append(record)
    values=[]
    for record in records:
        if args.metric=='connections':
            values.append(record.get('summary',{}).get('total',0))
        elif args.metric=='established':
            values.append(record.get('summary',{}).get('states',{}).get('ESTABLISHED',0))
        elif args.metric=='close_wait':
            values.append(record.get('summary',{}).get('states',{}).get('CLOSE_WAIT',0))
        elif args.metric=='anomalies':
            values.append(len(record.get('anomalies',[])))
        else:
            values.append(sum(x.get('delta',0) or 0 for x in record.get('counter_delta',[]) if args.metric.lower() in x.get('label','').lower()))
    report={'metric':args.metric,'samples':len(values),'distribution':quantiles(values),'histogram':histogram(values,args.buckets),'moving_average':moving_average(values,args.window),'exponential_average':exponential_average(values,args.alpha),'spikes':detect_spikes(values,args.threshold),'differences':series_differences(values)}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Metric:',args.metric)
        print('Samples:',len(values))
        print('Distribution:',report['distribution'])
        print('Spikes:',len(report['spikes']))
        print_table(report['spikes'],[('index','SAMPLE'),('value','VALUE'),('score','ROBUST Z')],args.limit)
    return 0


def command_capture(args):
    before=snapshot(args.timeout,False,False,False,False)
    time.sleep(args.delay)
    after=snapshot(args.timeout,False,False,False,False)
    result=snapshot_diff(before,after)
    result['state_transitions']=tcp_state_transitions(before['connections'],after['connections'])
    result['counter_categories']=classify_counter_deltas(result['tcp_counters'])
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Capture interval:',result['seconds'])
        print('Opened:',result['connections']['opened_count'])
        print('Closed:',result['connections']['closed_count'])
        print('State transitions:',len(result['state_transitions']))
        changes=[x for x in result['tcp_counters'] if x['delta'] is not None and x['delta']>0]
        print_table(changes,[('delta','DELTA'),('rate_per_second','RATE/S'),('label','COUNTER')],args.limit)
    return 0


def add_extended_commands(sub):
    x=sub.add_parser('audit',help='Read-only TCP heuristic security observations')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_audit)
    x=sub.add_parser('listeners',help='Correlate listening sockets with local processes')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--port',type=int)
    x.add_argument('--scope',choices=['wildcard','loopback','private','global','link_local','special','hostname_or_unknown'])
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_listeners)
    x=sub.add_parser('queues',help='Detect TCP send and receive queue pressure')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--threshold',type=int,default=65536)
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_queues)
    x=sub.add_parser('peers',help='Analyze TCP peer distribution and concentration')
    add_common(x)
    x.add_argument('--file')
    add_filter(x)
    x.set_defaults(func=command_peers)
    x=sub.add_parser('matrix',help='Build TCP state or local-to-remote peer matrices')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--type',choices=['state','peer'],default='state')
    add_filter(x)
    x.set_defaults(func=command_matrix)
    x=sub.add_parser('fingerprint',help='Fingerprint a system TCP configuration snapshot')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--include-connections',action='store_true')
    x.set_defaults(func=command_fingerprint)
    x=sub.add_parser('verify',help='Validate saved snapshot structure')
    add_common(x)
    x.add_argument('file')
    x.set_defaults(func=command_verify)
    x=sub.add_parser('inventory',help='Create a full local TCP inventory')
    add_common(x)
    x.add_argument('--file')
    x.set_defaults(func=command_inventory)
    x=sub.add_parser('analyze',help='Deep analysis of a saved snapshot')
    add_common(x)
    x.add_argument('file')
    x.add_argument('--queue-threshold',type=int,default=65536)
    add_filter(x)
    x.set_defaults(func=command_analyze)
    x=sub.add_parser('countertrend',help='Statistical trend analysis of JSONL samples')
    add_common(x)
    x.add_argument('file')
    x.add_argument('--metric',default='connections')
    x.add_argument('--buckets',type=int,default=10)
    x.add_argument('--window',type=int,default=5)
    x.add_argument('--alpha',type=float,default=.3)
    x.add_argument('--threshold',type=float,default=3.5)
    x.add_argument('--strict',action='store_true')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_countertrend)
    x=sub.add_parser('capture',help='Two-sample TCP counter and state capture')
    add_common(x)
    x.add_argument('--delay',type=float,default=5.0)
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_capture)

def parse_iso_time(value):
    return datetime.datetime.fromisoformat(value.replace('Z','+00:00'))


def time_gap(first,last):
    return max(0,(parse_iso_time(last)-parse_iso_time(first)).total_seconds())


def safe_regex(pattern):
    try:
        return re.compile(pattern,re.I)
    except re.error as e:
        raise ForensicsError(f'invalid regular expression: {e}')


def sanitize_address(value,mask_ipv4=24,mask_ipv6=64):
    try:
        address=ipaddress.ip_address(value.split('%')[0])
        bits=mask_ipv4 if address.version==4 else mask_ipv6
        network=ipaddress.ip_network(f'{address}/{bits}',strict=False)
        return str(network.network_address)+f'/{bits}'
    except ValueError:
        return value


def redact_snapshot(data,mode='mask'):
    copy=json.loads(json.dumps(data))
    for row in copy.get('connections',[]):
        for field in ('local','remote'):
            ep=row.get(field,{})
            if mode=='remove':
                ep['address']='REDACTED'
            else:
                ep['address']=sanitize_address(ep.get('address',''))
            ep['raw']=ep['address']+':'+str(ep.get('port'))
        row.pop('raw',None)
    for row in copy.get('process_sockets',[]):
        for field in ('local','remote'):
            ep=row.get(field,{})
            ep['address']='REDACTED' if mode=='remove' else sanitize_address(ep.get('address',''))
            ep['raw']=ep['address']+':'+str(ep.get('port'))
        row.pop('raw',None)
        if mode=='remove':
            row['user']='REDACTED'
            row['command']='REDACTED'
    for item in copy.get('commands',{}).values():
        item['stdout']=''
        item['stderr']=''
    copy['summary']=summarize_connections(copy.get('connections',[]))
    copy['anomalies']=anomalies(copy.get('connections',[]))
    copy['redaction']={'mode':mode,'timestamp':now(),'warning':'Redaction is best effort; review all fields before sharing'}
    return copy


def build_peer_graph(rows):
    nodes=collections.Counter()
    edges=collections.Counter()
    for row in rows:
        source=row['local']['address']
        target=row['remote']['address']
        nodes[source]+=1
        nodes[target]+=1
        edges[(source,target)]+=1
    return {'nodes':[{'id':name,'degree_weight':count,'scope':address_class(name)} for name,count in nodes.most_common()],'edges':[{'source':a,'target':b,'connections':n} for (a,b),n in edges.most_common()]}


def graph_dot(graph,max_edges=500):
    lines=['digraph tcp_connections {','  rankdir=LR;','  node [shape=ellipse];']
    def quote(value):
        return json.dumps(str(value))
    for node in graph['nodes']:
        lines.append(f'  {quote(node["id"])};')
    for edge in graph['edges'][:max_edges]:
        lines.append(f'  {quote(edge["source"])} -> {quote(edge["target"])} [label={quote(edge["connections"])}];')
    lines.append('}')
    return '\n'.join(lines)+'\n'


def time_series_from_jsonl(path,strict=False):
    records=[]
    with open(path,encoding='utf-8') as f:
        for number,line in enumerate(f,1):
            if not line.strip():
                continue
            try:
                obj=json.loads(line)
            except json.JSONDecodeError as e:
                if strict:
                    raise ForensicsError(f'line {number}: {e}')
                continue
            if obj.get('kind')!='sample':
                continue
            records.append(obj)
    return records


def interval_distribution(records):
    intervals=[]
    for a,b in zip(records,records[1:]):
        try:
            intervals.append(time_gap(a['timestamp'],b['timestamp']))
        except (KeyError,ValueError):
            continue
    return quantiles(intervals)


def summarize_watch_series(records):
    state_names=set()
    for record in records:
        state_names.update(record.get('summary',{}).get('states',{}))
    states={}
    for name in sorted(state_names):
        values=[r.get('summary',{}).get('states',{}).get(name,0) for r in records]
        states[name]={'distribution':quantiles(values),'spikes':detect_spikes(values),'trend':exponential_average(values)}
    opened=[r.get('connection_delta',{}).get('opened_count',0) for r in records]
    closed=[r.get('connection_delta',{}).get('closed_count',0) for r in records]
    total=[r.get('summary',{}).get('total',0) for r in records]
    return {'samples':len(records),'interval_seconds':interval_distribution(records),'states':states,'opened':quantiles(opened),'closed':quantiles(closed),'total':quantiles(total),'opened_total':sum(opened),'closed_total':sum(closed),'connection_churn':sum(opened)+sum(closed)}


def compare_sysctl_profiles(a,b):
    result=[]
    for key in sorted(set(a)|set(b)):
        old=a.get(key)
        new=b.get(key)
        if old!=new:
            result.append({'key':key,'before':old,'after':new,'category':sysctl_classification(key),'added':key not in a,'removed':key not in b})
    return result


def compare_interface_profiles(a,b):
    ia={x['name']:x for x in a}
    ib={x['name']:x for x in b}
    result=[]
    for name in sorted(set(ia)|set(ib)):
        old=ia.get(name)
        new=ib.get(name)
        if old!=new:
            result.append({'interface':name,'before':old,'after':new})
    return result


def compare_route_profiles(a,b):
    normalize=lambda rows:{(x.get('family'),x.get('destination'),x.get('gateway'),x.get('interface')) for x in rows}
    old=normalize(a)
    new=normalize(b)
    return {'added':[list(x) for x in sorted(new-old)],'removed':[list(x) for x in sorted(old-new)]}


def baseline_diff(a,b):
    return {'before':a.get('timestamp'),'after':b.get('timestamp'),'kernel_changed':a.get('uname')!=b.get('uname'),'kernel_before':a.get('uname'),'kernel_after':b.get('uname'),'sysctl_changes':compare_sysctl_profiles(a.get('sysctl',{}),b.get('sysctl',{})),'interface_changes':compare_interface_profiles(a.get('interfaces',[]),b.get('interfaces',[])),'route_changes':compare_route_profiles(a.get('routes',[]),b.get('routes',[])),'fingerprint_before':snapshot_fingerprint(a),'fingerprint_after':snapshot_fingerprint(b)}


def parse_procstat_file_descriptors(text):
    rows=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)<6 or not parts[0].isdigit():
            continue
        rows.append({'pid':int(parts[0]),'command':parts[1],'fd':parts[2],'type':parts[3],'raw':line})
    return rows


def procstat_pid(pid,timeout=8):
    if not isinstance(pid,int) or pid<=0:
        raise ForensicsError('pid must be a positive integer')
    result={}
    for name,args in {'files':['procstat','-f',str(pid)],'arguments':['procstat','-c',str(pid)],'threads':['procstat','-t',str(pid)],'resource':['procstat','-r',str(pid)]}.items():
        r=run(args,timeout)
        result[name]={'ok':r.returncode==0,'stdout':r.stdout,'stderr':r.stderr}
    result['files_parsed']=parse_procstat_file_descriptors(result['files']['stdout'])
    return result


def network_service_inventory(s):
    listeners=listener_inventory(s.get('connections',[]),s.get('process_sockets',[]))
    by_port=collections.defaultdict(list)
    for listener in listeners:
        by_port[(listener['protocol'],listener['port'])].append(listener)
    result=[]
    for (protocol,port),entries in sorted(by_port.items(),key=lambda x:(str(x[0][1]),x[0][0])):
        result.append({'protocol':protocol,'port':port,'bindings':[x['address'] for x in entries],'scopes':[x['scope'] for x in entries],'pids':sorted(set(p['pid'] for x in entries for p in x['processes'])),'commands':sorted(set(p['command'] for x in entries for p in x['processes']))})
    return result


def policy_evaluate(s,policy):
    findings=[]
    services=network_service_inventory(s)
    allowed=set(int(x) for x in policy.get('allowed_listen_ports',[]))
    blocked=set(int(x) for x in policy.get('blocked_listen_ports',[]))
    for service in services:
        port=service['port']
        if port is None:
            continue
        if allowed and port not in allowed:
            findings.append({'kind':'unexpected_listener','port':port,'severity':'warning','service':service})
        if port in blocked:
            findings.append({'kind':'blocked_port_listening','port':port,'severity':'warning','service':service})
        if policy.get('forbid_wildcard_listeners') and 'wildcard' in service['scopes']:
            findings.append({'kind':'wildcard_listener','port':port,'severity':'warning','service':service})
    states=collections.Counter(r['state'] for r in s.get('connections',[]))
    for state,limit in policy.get('max_states',{}).items():
        current=states.get(normalize_state(state),0)
        if current>limit:
            findings.append({'kind':'state_threshold','state':state,'observed':current,'limit':limit,'severity':'warning'})
    for key,expected in policy.get('expected_sysctl',{}).items():
        actual=s.get('sysctl',{}).get(key)
        if actual!=expected:
            findings.append({'kind':'sysctl_mismatch','key':key,'expected':expected,'observed':actual,'severity':'warning'})
    return {'passed':not findings,'findings':findings,'services':len(services),'policy':policy.get('name','unnamed'),'timestamp':now()}


def policy_template():
    return {'name':'example-local-policy','allowed_listen_ports':[],'blocked_listen_ports':[],'forbid_wildcard_listeners':False,'max_states':{'CLOSE_WAIT':100,'SYN_RECEIVED':100},'expected_sysctl':{}}


def command_redact(args):
    data=read_json(args.file)
    result=redact_snapshot(data,args.mode)
    write_json(args.output,result)
    return 0


def command_graph(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    graph=build_peer_graph(filter_connections(s.get('connections',[]),args))
    if args.format=='dot':
        value=graph_dot(graph,args.limit)
        if args.output:
            pathlib.Path(args.output).write_text(value,encoding='utf-8')
        else:
            print(value,end='')
    elif args.output or args.json:
        write_json(args.output,graph)
    else:
        print('Nodes:',len(graph['nodes']))
        print('Edges:',len(graph['edges']))
        print_table(graph['edges'],[('source','SOURCE'),('target','TARGET'),('connections','CONNECTIONS')],args.limit)
    return 0


def command_baseline(args):
    before=read_json(args.before)
    after=read_json(args.after) if args.after else snapshot(args.timeout,False,True,True,True)
    result=baseline_diff(before,after)
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Kernel changed:',result['kernel_changed'])
        print('Sysctl changes:',len(result['sysctl_changes']))
        print('Interface changes:',len(result['interface_changes']))
        print('Routes added:',len(result['route_changes']['added']))
        print('Routes removed:',len(result['route_changes']['removed']))
        print_table(result['sysctl_changes'],[('key','SYSCTL'),('before','BEFORE'),('after','AFTER'),('category','CATEGORY')],args.limit)
    return 0


def command_procstat(args):
    result=procstat_pid(args.pid,args.timeout)
    if args.json or args.output:
        write_json(args.output,{'pid':args.pid,'timestamp':now(),'procstat':result})
    else:
        for name,section in result.items():
            if name=='files_parsed':
                continue
            print('\n'+name.upper())
            print(section['stdout'][:args.max_bytes] if section['ok'] else section['stderr'])
    return 0


def command_policy(args):
    if args.template:
        write_json(args.output,policy_template())
        return 0
    if not args.policy:
        raise ForensicsError('--policy is required unless --template is used')
    policy=read_json(args.policy)
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,True)
    result=policy_evaluate(s,policy)
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Policy:',result['policy'])
        print('Passed:',result['passed'])
        print('Findings:',len(result['findings']))
        for finding in result['findings'][:args.limit]:
            print(json.dumps(finding,sort_keys=True))
    return 0 if result['passed'] else 1


def command_services(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,False)
    result=network_service_inventory(s)
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'services':result})
    else:
        print_table([{'proto':r['protocol'],'port':r['port'],'bindings':','.join(r['bindings']),'pids':','.join(map(str,r['pids'])),'commands':','.join(r['commands'])} for r in result],[('proto','PROTO'),('port','PORT'),('bindings','BINDINGS'),('pids','PIDS'),('commands','COMMANDS')],args.limit)
    return 0


def command_series(args):
    records=time_series_from_jsonl(args.file,args.strict)
    result=summarize_watch_series(records)
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Samples:',result['samples'])
        print('Intervals:',result['interval_seconds'])
        print('Total connections:',result['total'])
        print('Opened:',result['opened_total'])
        print('Closed:',result['closed_total'])
        print('Churn:',result['connection_churn'])
        for state,info in result['states'].items():
            print(state,info['distribution'],'spikes:',len(info['spikes']))
    return 0


def add_more_commands(sub):
    x=sub.add_parser('redact',help='Best-effort redaction of a snapshot before sharing')
    x.add_argument('file')
    x.add_argument('--mode',choices=['mask','remove'],default='mask')
    x.add_argument('--output',required=True)
    x.set_defaults(func=command_redact)
    x=sub.add_parser('graph',help='Build a local TCP connection graph, JSON or DOT')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--format',choices=['json','dot'],default='json')
    add_filter(x)
    x.set_defaults(func=command_graph)
    x=sub.add_parser('baseline',help='Compare saved baseline with current or saved system')
    add_common(x)
    x.add_argument('before')
    x.add_argument('--after')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_baseline)
    x=sub.add_parser('procstat',help='Read-only process descriptor and thread diagnostics')
    add_common(x)
    x.add_argument('pid',type=int)
    x.add_argument('--max-bytes',type=int,default=30000)
    x.set_defaults(func=command_procstat)
    x=sub.add_parser('policy',help='Evaluate a local declarative TCP inspection policy')
    add_common(x)
    x.add_argument('--template',action='store_true')
    x.add_argument('--policy')
    x.add_argument('--file')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_policy)
    x=sub.add_parser('services',help='Inventory locally listening TCP services')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_services)
    x=sub.add_parser('series',help='Summarize JSONL time series and state trends')
    add_common(x)
    x.add_argument('file')
    x.add_argument('--strict',action='store_true')
    x.set_defaults(func=command_series)

def parse_netstat_mbuf(text):
    counters=[]
    for line in text.splitlines():
        m=re.match(r'^\s*([\d,]+)\s+(.+)$',line)
        if m:
            counters.append({'value':int(m.group(1).replace(',','')),'label':m.group(2).strip()})
    return counters


def parse_netstat_protocols(text):
    result=collections.defaultdict(list)
    current='unknown'
    for line in text.splitlines():
        if re.match(r'^[a-z][\w-]*:\s*$',line):
            current=line.strip()[:-1]
        elif re.match(r'^\s*\d',line):
            m=re.match(r'^\s*([\d,]+)\s+(.+)$',line)
            if m:
                result[current].append({'value':int(m.group(1).replace(',','')),'label':m.group(2).strip()})
    return dict(result)


def parse_ifconfig_statistics(text):
    result=[]
    current=None
    for line in text.splitlines():
        if line and not line[0].isspace() and ': flags=' in line:
            current=line.split(':',1)[0]
        elif current:
            for name,value in re.findall(r'\b([a-z][a-z0-9_-]+)\s+(\d+)\b',line,re.I):
                if name.lower() in ('mtu','metric','nd6','id'):
                    result.append({'interface':current,'metric':name.lower(),'value':int(value)})
    return result


def parse_ps_output(text):
    rows=[]
    for line in text.splitlines():
        p=line.split(None,5)
        if len(p)<6 or not p[0].isdigit():
            continue
        rows.append({'pid':int(p[0]),'ppid':safe_number(p[1]),'user':p[2],'state':p[3],'cpu':safe_number(p[4]),'command':p[5]})
    return rows


def parse_netstat_interface_table(text):
    rows=[]
    for line in text.splitlines():
        p=line.split()
        if len(p)<7 or p[0].lower()=='name':
            continue
        if p[0].startswith(('lo','em','igb','ix','vtnet','re','bge','lagg','bridge','epair','tap','tun','vmx')):
            rows.append({'interface':p[0],'mtu':safe_number(p[1]),'network':p[2],'address':p[3],'raw':line})
    return rows


def gather_kernel_diagnostics(timeout=8):
    commands={
        'mbuf':['netstat','-m'],
        'protocols':['netstat','-s'],
        'interfaces':['netstat','-i'],
        'processes':['ps','-axo','pid,ppid,user,state,%cpu,command'],
        'tcp_cc':['sysctl','net.inet.tcp.cc'],
        'tcp_functions':['sysctl','net.inet.tcp.functions'],
        'tcp_blackhole':['sysctl','net.inet.tcp.blackhole'],
        'tcp_sack':['sysctl','net.inet.tcp.sack'],
        'tcp_ecn':['sysctl','net.inet.tcp.ecn'],
        'tcp_rfc1323':['sysctl','net.inet.tcp.rfc1323'],
        'tcp_keepidle':['sysctl','net.inet.tcp.keepidle'],
        'tcp_keepintvl':['sysctl','net.inet.tcp.keepintvl'],
        'tcp_msl':['sysctl','net.inet.tcp.msl'],
        'tcp_delayed_ack':['sysctl','net.inet.tcp.delayed_ack'],
    }
    results={name:run(argv,timeout) for name,argv in commands.items()}
    get=lambda name:results[name].stdout if results[name].returncode==0 else ''
    return {'timestamp':now(),'commands':{k:v.as_dict() for k,v in results.items()},'mbuf':parse_netstat_mbuf(get('mbuf')),'protocols':parse_netstat_protocols(get('protocols')),'interfaces':parse_netstat_interface_table(get('interfaces')),'processes':parse_ps_output(get('processes')),'tcp_tunables':{k:parse_sysctl(get(k)) for k in commands if k.startswith('tcp_')}}


def diagnostic_issues(data):
    issues=[]
    for name,result in data.get('commands',{}).items():
        if result.get('returncode')!=0:
            issues.append({'kind':'command_unavailable','command':name,'error':result.get('stderr'),'severity':'informational'})
    for counter in data.get('mbuf',[]):
        label=counter['label'].lower()
        if any(x in label for x in ('denied','failed','dropped','exhausted')) and counter['value']>0:
            issues.append({'kind':'mbuf_pressure_history','counter':counter,'severity':'informational','note':'Cumulative counter alone does not establish current pressure'})
    return issues


def command_kernel(args):
    data=gather_kernel_diagnostics(args.timeout)
    data['observations']=diagnostic_issues(data)
    if args.json or args.output:
        write_json(args.output,data)
    else:
        print('Kernel TCP diagnostics:',data['timestamp'])
        print('Mbuf counters:',len(data['mbuf']))
        print('Protocols:',len(data['protocols']))
        print('Processes:',len(data['processes']))
        print('Observations:',len(data['observations']))
        print('TCP tunables:')
        for name,values in data['tcp_tunables'].items():
            print(' ',name,values)
        print_table(data['mbuf'],[('value','COUNT'),('label','MBUF COUNTER')],args.limit)
    return 0


def command_mbuf(args):
    r=run(['netstat','-m'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'netstat -m failed')
    rows=parse_netstat_mbuf(r.stdout)
    if args.match:
        rows=[x for x in rows if args.match.lower() in x['label'].lower()]
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'counters':rows,'raw':r.stdout if args.include_raw else None})
    else:
        print_table(rows,[('value','COUNT'),('label','DESCRIPTION')],args.limit)
        if not rows:
            print(r.stdout)
    return 0


def command_protocols(args):
    r=run(['netstat','-s'],args.timeout)
    if r.returncode:
        raise ForensicsError(r.stderr or 'netstat -s failed')
    result=parse_netstat_protocols(r.stdout)
    if args.protocol:
        result={k:v for k,v in result.items() if args.protocol.lower() in k.lower()}
    if args.match:
        result={k:[x for x in v if args.match.lower() in x['label'].lower()] for k,v in result.items()}
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'protocols':result})
    else:
        for protocol,rows in result.items():
            print('\n'+protocol.upper())
            print_table(rows,[('value','COUNT'),('label','DESCRIPTION')],args.limit)
    return 0


def compare_kernel_diagnostics(a,b):
    def index(rows):
        return {x['label']:x['value'] for x in rows}
    before=index(a.get('mbuf',[]))
    after=index(b.get('mbuf',[]))
    mbuf=[]
    for key in sorted(set(before)|set(after)):
        mbuf.append({'label':key,'before':before.get(key),'after':after.get(key),'delta':delta(after.get(key),before.get(key))})
    proto=[]
    for protocol in sorted(set(a.get('protocols',{}))|set(b.get('protocols',{}))):
        first=index(a.get('protocols',{}).get(protocol,[]))
        second=index(b.get('protocols',{}).get(protocol,[]))
        for key in sorted(set(first)|set(second)):
            proto.append({'protocol':protocol,'label':key,'before':first.get(key),'after':second.get(key),'delta':delta(second.get(key),first.get(key))})
    return {'timestamp':now(),'mbuf_changes':mbuf,'protocol_changes':proto,'process_count_before':len(a.get('processes',[])),'process_count_after':len(b.get('processes',[]))}


def command_kernel_diff(args):
    before=read_json(args.before)
    after=read_json(args.after)
    report=compare_kernel_diagnostics(before,after)
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Mbuf counters changed:',sum(x['delta'] not in (None,0) for x in report['mbuf_changes']))
        print('Protocol counters changed:',sum(x['delta'] not in (None,0) for x in report['protocol_changes']))
        rows=[x for x in report['protocol_changes'] if x['delta'] not in (None,0)]
        print_table(rows,[('protocol','PROTOCOL'),('delta','DELTA'),('label','COUNTER')],args.limit)
    return 0


def describe_tcp_state(state):
    descriptions={
        'CLOSED':'No active TCP connection exists for this endpoint',
        'LISTEN':'Passive socket is waiting for incoming connection requests',
        'SYN_SENT':'Active opener sent SYN and is awaiting handshake completion',
        'SYN_RECEIVED':'Passive or simultaneous opener received SYN and awaits handshake completion',
        'ESTABLISHED':'Bidirectional data transfer is permitted',
        'CLOSE_WAIT':'Remote peer sent FIN; local application has not closed its endpoint',
        'FIN_WAIT_1':'Local endpoint initiated close and awaits acknowledgment or peer FIN',
        'FIN_WAIT_2':'Local FIN acknowledged; waiting for remote FIN',
        'CLOSING':'Both endpoints have sent FIN and final acknowledgment is pending',
        'LAST_ACK':'Local endpoint sent FIN after peer close and awaits acknowledgment',
        'TIME_WAIT':'Connection retained temporarily to absorb delayed packets',
    }
    return descriptions.get(normalize_state(state),'Unknown TCP state')


def explain_stat(label):
    name=label.lower()
    if 'retrans' in name:
        return 'Retransmissions can result from loss, reordering, or acknowledgment timing; compare rates over intervals'
    if 'duplicate' in name:
        return 'Duplicate observations may reflect retransmission, reordering, or receiver behavior'
    if 'timeout' in name:
        return 'Timeout counters are cumulative; sample intervals to identify ongoing events'
    if 'reset' in name:
        return 'TCP resets can be normal application behavior or indicate unexpected termination'
    if 'drop' in name:
        return 'Drops have many causes; correlate with queues, resource limits, and protocol state'
    if 'window' in name:
        return 'Window behavior reflects receiver flow control and may affect throughput'
    if 'sack' in name:
        return 'Selective acknowledgments help recover efficiently from packet loss'
    if 'ecn' in name:
        return 'Explicit Congestion Notification allows congestion signaling without packet loss'
    if 'syn' in name:
        return 'SYN counters relate to connection setup and should be interpreted with traffic volume'
    return 'Interpret this cumulative counter alongside a time delta and application workload'


def command_explain(args):
    if args.state:
        print(normalize_state(args.state)+': '+describe_tcp_state(args.state))
        return 0
    if args.counter:
        print(args.counter+': '+explain_stat(args.counter))
        return 0
    for state in TCP_STATES:
        print(f'{state:<18} {describe_tcp_state(state)}')
    return 0


def counter_alerts(before,after,elapsed,thresholds):
    rows=compare_counters(before,after,elapsed)
    findings=[]
    for rule in thresholds:
        pattern=rule.get('pattern','')
        if not pattern:
            continue
        matcher=safe_regex(pattern)
        minimum=rule.get('minimum_rate',0)
        for row in rows:
            if not matcher.search(row['label']):
                continue
            r=row['rate_per_second']
            if r is not None and r>=minimum:
                findings.append({'rule':rule.get('name',pattern),'label':row['label'],'rate_per_second':r,'threshold':minimum,'delta':row['delta'],'section':row['section']})
    return findings


def default_counter_rules():
    return [
        {'name':'tcp_retransmission_activity','pattern':'retrans|resent|rexmit','minimum_rate':10},
        {'name':'tcp_dropped_packets','pattern':'drop|discard','minimum_rate':10},
        {'name':'tcp_timeout_activity','pattern':'timeout|timed out','minimum_rate':5},
        {'name':'tcp_reset_activity','pattern':'reset|rst','minimum_rate':20},
        {'name':'tcp_invalid_packets','pattern':'invalid|bad|incorrect','minimum_rate':1},
    ]


def command_alerts(args):
    if args.template:
        write_json(args.output,{'rules':default_counter_rules()})
        return 0
    a=read_json(args.before)
    b=read_json(args.after)
    elapsed=time_gap(a['timestamp'],b['timestamp'])
    rules=read_json(args.rules)['rules'] if args.rules else default_counter_rules()
    findings=counter_alerts(a.get('tcp_stats',[]),b.get('tcp_stats',[]),elapsed,rules)
    report={'elapsed_seconds':elapsed,'rules':len(rules),'findings':findings,'interpretation':'Threshold alerts are heuristics, not evidence of compromise'}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        print('Elapsed:',elapsed,'seconds')
        print('Triggered:',len(findings))
        print_table(findings,[('rule','RULE'),('rate_per_second','RATE/S'),('threshold','THRESHOLD'),('label','COUNTER')],args.limit)
    return 0 if not findings else 1


def compare_peers(a,b):
    first=collections.Counter(x['remote']['address'] for x in a)
    second=collections.Counter(x['remote']['address'] for x in b)
    return [{'peer':peer,'before':first.get(peer,0),'after':second.get(peer,0),'delta':second.get(peer,0)-first.get(peer,0)} for peer in sorted(set(first)|set(second))]


def compare_ports(a,b):
    first=collections.Counter(x['local']['port'] for x in a)
    second=collections.Counter(x['local']['port'] for x in b)
    return [{'port':port,'before':first.get(port,0),'after':second.get(port,0),'delta':second.get(port,0)-first.get(port,0)} for port in sorted(set(first)|set(second),key=str)]


def command_peer_diff(args):
    a=read_json(args.before)
    b=read_json(args.after)
    rows=compare_peers(a.get('connections',[]),b.get('connections',[])) if args.type=='peer' else compare_ports(a.get('connections',[]),b.get('connections',[]))
    if args.only_changes:
        rows=[x for x in rows if x['delta']]
    rows.sort(key=lambda x:-abs(x['delta']))
    if args.json or args.output:
        write_json(args.output,{'type':args.type,'rows':rows})
    else:
        key='peer' if args.type=='peer' else 'port'
        print_table(rows,[(key,key.upper()),('before','BEFORE'),('after','AFTER'),('delta','DELTA')],args.limit)
    return 0


def add_kernel_commands(sub):
    x=sub.add_parser('kernel',help='Inspect FreeBSD kernel network resource diagnostics')
    add_common(x)
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_kernel)
    x=sub.add_parser('mbuf',help='Inspect local mbuf allocator statistics')
    add_common(x)
    x.add_argument('--match')
    x.add_argument('--include-raw',action='store_true')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_mbuf)
    x=sub.add_parser('protocols',help='Inspect all local protocol counters')
    add_common(x)
    x.add_argument('--protocol')
    x.add_argument('--match')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_protocols)
    x=sub.add_parser('kernel-diff',help='Compare two kernel diagnostics captures')
    add_common(x)
    x.add_argument('before')
    x.add_argument('after')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_kernel_diff)
    x=sub.add_parser('explain',help='Explain TCP states or statistical counters')
    x.add_argument('--state')
    x.add_argument('--counter')
    x.set_defaults(func=command_explain)
    x=sub.add_parser('alerts',help='Evaluate offline TCP counter rate alert rules')
    add_common(x)
    x.add_argument('before',nargs='?')
    x.add_argument('after',nargs='?')
    x.add_argument('--rules')
    x.add_argument('--template',action='store_true')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_alerts)
    x=sub.add_parser('peer-diff',help='Compare TCP peer or local port populations')
    add_common(x)
    x.add_argument('before')
    x.add_argument('after')
    x.add_argument('--type',choices=['peer','port'],default='peer')
    x.add_argument('--only-changes',action='store_true')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_peer_diff)

def tcp_port_class(port):
    if not isinstance(port,int):
        return 'unknown'
    if port<0 or port>65535:
        return 'invalid'
    if port<=1023:
        return 'well_known'
    if port<=49151:
        return 'registered'
    return 'dynamic'


def tcp_port_profile(rows):
    result=collections.defaultdict(lambda:{'count':0,'states':collections.Counter(),'peers':set(),'classes':collections.Counter()})
    for row in rows:
        port=row['local']['port']
        entry=result[port]
        entry['count']+=1
        entry['states'][row['state']]+=1
        entry['peers'].add(row['remote']['address'])
        entry['classes'][tcp_port_class(port)]+=1
    return [{'port':k,'class':tcp_port_class(k),'connections':v['count'],'unique_peers':len(v['peers']),'states':dict(v['states'])} for k,v in sorted(result.items(),key=lambda x:-x[1]['count'])]


def tcp_exposure_summary(rows):
    listeners=[r for r in rows if r['state']=='LISTEN']
    scopes=collections.Counter(address_class(r['local']['address']) for r in listeners)
    ports=collections.Counter(tcp_port_class(r['local']['port']) for r in listeners)
    return {'listeners':len(listeners),'scopes':dict(scopes),'port_classes':dict(ports),'wildcard_listeners':[socket_flow_key(r) for r in listeners if r['local']['wildcard']],'loopback_listeners':[socket_flow_key(r) for r in listeners if is_loopback_address(r['local']['address'])]}


def summarize_process_ownership(process_sockets):
    by_pid=collections.defaultdict(list)
    for row in process_sockets:
        by_pid[row['pid']].append(row)
    results=[]
    for pid,rows in by_pid.items():
        results.append({'pid':pid,'command':rows[0]['command'],'user':rows[0]['user'],'sockets':len(rows),'protocols':dict(collections.Counter(r['protocol'] for r in rows)),'local_ports':sorted(set(str(r['local']['port']) for r in rows)),'remote_peers':len(set(r['remote']['address'] for r in rows))})
    return sorted(results,key=lambda x:(-x['sockets'],x['pid']))


def compare_process_ownership(a,b):
    before={x['pid']:x for x in summarize_process_ownership(a)}
    after={x['pid']:x for x in summarize_process_ownership(b)}
    changes=[]
    for pid in sorted(set(before)|set(after)):
        x=before.get(pid)
        y=after.get(pid)
        if x!=y:
            changes.append({'pid':pid,'before':x,'after':y,'socket_delta':(y['sockets'] if y else 0)-(x['sockets'] if x else 0)})
    return changes


def local_health_score(s):
    rows=s.get('connections',[])
    state=collections.Counter(r['state'] for r in rows)
    queues=queue_pressure(rows,262144)
    score=100
    penalties=[]
    if state['CLOSE_WAIT']>=50:
        score-=15
        penalties.append('many_close_wait_connections')
    if state['SYN_RECEIVED']>=100:
        score-=15
        penalties.append('many_pending_inbound_handshakes')
    if state['SYN_SENT']>=100:
        score-=10
        penalties.append('many_pending_outbound_handshakes')
    if len(queues)>=10:
        score-=15
        penalties.append('multiple_large_socket_queues')
    failures=[k for k,v in s.get('commands',{}).items() if v.get('returncode')!=0]
    if failures:
        score-=min(25,5*len(failures))
        penalties.append('diagnostic_commands_failed')
    return {'score':max(0,score),'penalties':penalties,'command_failures':failures,'interpretation':'Heuristic snapshot quality and TCP pressure indicator, not a security or availability guarantee'}


def command_ports(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    rows=filter_connections(s.get('connections',[]),args)
    result=tcp_port_profile(rows)
    if args.classification:
        result=[x for x in result if x['class']==args.classification]
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'ports':result})
    else:
        print_table(result,[('port','PORT'),('class','CLASS'),('connections','CONNECTIONS'),('unique_peers','PEERS')],args.limit)
    return 0


def command_exposure(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,False)
    result=tcp_exposure_summary(s.get('connections',[]))
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Listeners:',result['listeners'])
        print('Scopes:',result['scopes'])
        print('Port classes:',result['port_classes'])
        print('Wildcard listeners:')
        for flow in result['wildcard_listeners'][:args.limit]:
            print(' ',flow)
    return 0


def command_owners(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,True,False,False,False)
    rows=s.get('process_sockets',[])
    if args.user:
        rows=[x for x in rows if x['user']==args.user]
    result=summarize_process_ownership(rows)
    if args.json or args.output:
        write_json(args.output,{'timestamp':now(),'processes':result})
    else:
        print_table(result,[('pid','PID'),('command','COMMAND'),('user','USER'),('sockets','SOCKETS'),('remote_peers','PEERS')],args.limit)
    return 0


def command_owners_diff(args):
    before=read_json(args.before)
    after=read_json(args.after)
    changes=compare_process_ownership(before.get('process_sockets',[]),after.get('process_sockets',[]))
    if args.json or args.output:
        write_json(args.output,{'changes':changes})
    else:
        print_table(changes,[('pid','PID'),('socket_delta','SOCKET DELTA')],args.limit)
    return 0


def command_health(args):
    s=read_json(args.file) if args.file else snapshot(args.timeout,False,False,False,False)
    result=local_health_score(s)
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('Heuristic health score:',result['score'])
        print('Penalties:',', '.join(result['penalties']) if result['penalties'] else 'none')
        print('Command failures:',', '.join(result['command_failures']) if result['command_failures'] else 'none')
        print(result['interpretation'])
    return 0


def command_digest(args):
    path=pathlib.Path(args.file)
    digest=hashlib.new(args.algorithm)
    size=0
    with path.open('rb') as f:
        while True:
            block=f.read(1024*1024)
            if not block:
                break
            digest.update(block)
            size+=len(block)
    result={'file':str(path),'algorithm':args.algorithm,'digest':digest.hexdigest(),'size_bytes':size}
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print(args.algorithm+':',result['digest'])
        print('Bytes:',size)
    return 0


def add_final_commands(sub):
    x=sub.add_parser('ports',help='Analyze local TCP port populations')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--classification',choices=['well_known','registered','dynamic','unknown','invalid'])
    add_filter(x)
    x.set_defaults(func=command_ports)
    x=sub.add_parser('exposure',help='Describe local TCP listener binding scope')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_exposure)
    x=sub.add_parser('owners',help='Aggregate TCP sockets by local process')
    add_common(x)
    x.add_argument('--file')
    x.add_argument('--user')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_owners)
    x=sub.add_parser('owners-diff',help='Compare local process socket ownership snapshots')
    add_common(x)
    x.add_argument('before')
    x.add_argument('after')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_owners_diff)
    x=sub.add_parser('health',help='Compute a heuristic TCP snapshot pressure score')
    add_common(x)
    x.add_argument('--file')
    x.set_defaults(func=command_health)
    x=sub.add_parser('digest',help='Calculate a local capture file checksum')
    x.add_argument('file')
    x.add_argument('--algorithm',choices=['sha256','sha512','blake2b'],default='sha256')
    x.add_argument('--json',action='store_true')
    x.add_argument('--output')
    x.set_defaults(func=command_digest)

def detailed_selftests():
    tests=[]
    def verify(name,condition):
        tests.append({'name':name,'passed':bool(condition)})
    verify('port_well_known',tcp_port_class(443)=='well_known')
    verify('port_registered',tcp_port_class(8080)=='registered')
    verify('port_dynamic',tcp_port_class(60000)=='dynamic')
    verify('port_invalid',tcp_port_class(70000)=='invalid')
    verify('address_loopback',address_class('127.0.0.1')=='loopback')
    verify('address_wildcard',address_class('*')=='wildcard')
    verify('address_private',address_class('192.168.1.1')=='private')
    verify('address_mask',sanitize_address('192.168.1.5')=='192.168.1.0/24')
    verify('moving_average',moving_average([1,2,3],2)==[1.0,1.5,2.5])
    verify('exponential_average',exponential_average([10],.5)==[10.0])
    verify('series_differences',series_differences([1,4,8])==[3,4])
    verify('histogram',sum(x['count'] for x in histogram([1,2,3],2))==3)
    verify('gini_equal',gini([1,1,1])==0)
    verify('herfindahl_equal',herfindahl([1,1])==.5)
    verify('fairness_equal',jain_fairness([1,1])==1)
    verify('state_description',bool(describe_tcp_state('ESTABLISHED')))
    verify('stat_explanation',bool(explain_stat('retransmissions')))
    verify('policy_template',isinstance(policy_template(),dict))
    verify('default_alert_rules',len(default_counter_rules())>=3)
    verify('mbuf_parser',parse_netstat_mbuf('12 mbufs in use')[0]['value']==12)
    verify('protocol_parser',parse_netstat_protocols('tcp:\n  5 packets sent')['tcp'][0]['value']==5)
    verify('port_profile_empty',tcp_port_profile([])==[])
    verify('exposure_empty',tcp_exposure_summary([])['listeners']==0)
    verify('process_ownership_empty',summarize_process_ownership([])==[])
    verify('process_comparison_empty',compare_process_ownership([],[])==[])
    verify('peer_comparison_empty',compare_peers([],[])==[])
    verify('port_comparison_empty',compare_ports([],[])==[])
    verify('graph_empty',build_peer_graph([])['edges']==[])
    verify('graph_dot',graph_dot({'nodes':[],'edges':[]}).startswith('digraph'))
    verify('state_matrix_empty',state_matrix([])=={})
    verify('connection_matrix_empty',connection_matrix([])=={})
    verify('queue_pressure_empty',queue_pressure([])==[])
    verify('risk_indicators_empty',connection_risk_indicators([])==[])
    verify('counter_rules_empty',counter_alerts([],[],1,[])==[])
    verify('numeric_suffix',parse_numeric_suffix('1k')==1024)
    verify('snapshot_schema_validation',not verify_snapshot({})['valid'])
    verify('tcp_health_empty',local_health_score({'connections':[]})['score']==100)
    verify('time_gap',time_gap('2026-01-01T00:00:00+00:00','2026-01-01T00:00:10+00:00')==10)
    verify('stats_categories',isinstance(sysctl_inventory({}),dict))
    verify('counter_delta_empty',compare_counters([],[],1)==[])
    return tests


def command_extended_selftest(args):
    try:
        results=detailed_selftests()
    except Exception as e:
        print('Extended selftest exception:',str(e),file=sys.stderr)
        return 1
    passed=sum(x['passed'] for x in results)
    report={'passed':passed,'total':len(results),'tests':results}
    if args.json or args.output:
        write_json(args.output,report)
    else:
        for test in results:
            print('PASS' if test['passed'] else 'FAIL',test['name'])
        print(f'{passed}/{len(results)} passed')
    return 0 if passed==len(results) else 1


def add_test_commands(sub):
    x=sub.add_parser('extended-selftest',help='Run extended offline analysis and parser regression checks')
    add_common(x)
    x.set_defaults(func=command_extended_selftest)

def command_quick(args):
    s=snapshot(args.timeout,True,False,False,False)
    rows=s.get('connections',[])
    owners=summarize_process_ownership(s.get('process_sockets',[]))
    summary=summarize_connections(rows)
    result={'timestamp':s['timestamp'],'host':s['host'],'kernel':s['uname'],'connections':summary,'listeners':tcp_exposure_summary(rows),'top_processes':owners[:10],'queue_pressure':queue_pressure(rows,args.threshold)[:10],'health':local_health_score(s),'tcp_stats':summarize_tcp_stats(s.get('tcp_stats',[]))}
    if args.json or args.output:
        write_json(args.output,result)
    else:
        print('TCP Forensics BSD',VERSION)
        print('Host:',result['host'])
        print('Kernel:',result['kernel'])
        print_summary(summary)
        print('Listeners:',result['listeners']['listeners'])
        print('Wildcard listeners:',len(result['listeners']['wildcard_listeners']))
        print('Queue pressure findings:',len(result['queue_pressure']))
        print('Heuristic health:',result['health']['score'])
        print('Top processes:')
        print_table(result['top_processes'],[('pid','PID'),('command','COMMAND'),('sockets','SOCKETS')],10)
    return 0


def add_quick_command(sub):
    x=sub.add_parser('quick',help='Fast local TCP overview without full sysctl collection')
    add_common(x)
    x.add_argument('--threshold',type=int,default=65536)
    x.set_defaults(func=command_quick)

def add_common(p,output=True):
    p.add_argument('--timeout',type=float,default=8.0)
    p.add_argument('--json',action='store_true')
    if output:
        p.add_argument('--output')


def add_filter(p):
    p.add_argument('--state')
    p.add_argument('--protocol')
    p.add_argument('--port',type=int)
    p.add_argument('--address')
    p.add_argument('--match')
    p.add_argument('--limit',type=int,default=100)


def parser():
    p=argparse.ArgumentParser(prog='tcp-forensics-bsd',description='Read-only FreeBSD TCP forensics and kernel telemetry')
    p.add_argument('--version',action='version',version=VERSION)
    sub=p.add_subparsers(dest='command',required=True)
    x=sub.add_parser('doctor',help='Check host and tool availability')
    add_common(x)
    x.set_defaults(func=command_doctor)
    x=sub.add_parser('selftest',help='Run portable parser and analysis tests')
    add_common(x)
    x.set_defaults(func=command_selftest)
    x=sub.add_parser('snapshot',help='Capture a comprehensive read-only snapshot')
    add_common(x)
    x.add_argument('--no-processes',action='store_true')
    x.add_argument('--no-interfaces',action='store_true')
    x.add_argument('--no-routes',action='store_true')
    x.add_argument('--no-sysctl',action='store_true')
    x.set_defaults(func=command_snapshot)
    x=sub.add_parser('sockets',help='Inspect TCP sockets and state')
    add_common(x)
    add_filter(x)
    x.set_defaults(func=command_sockets)
    x=sub.add_parser('stats',help='Inspect TCP stack counters')
    add_common(x)
    x.add_argument('--match')
    x.add_argument('--category',choices=sorted(STAT_CATEGORIES))
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_stats)
    x=sub.add_parser('sysctl',help='Inspect TCP sysctl values')
    add_common(x)
    x.add_argument('keys',nargs='*')
    x.add_argument('--match')
    x.add_argument('--limit',type=int,default=200)
    x.set_defaults(func=command_sysctl)
    x=sub.add_parser('processes',help='Correlate TCP sockets with processes')
    add_common(x)
    x.add_argument('--pid',type=int)
    x.add_argument('--match')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_processes)
    x=sub.add_parser('routes',help='Inspect local routing table')
    add_common(x)
    x.add_argument('--family',choices=['ipv4','ipv6'])
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_routes)
    x=sub.add_parser('interfaces',help='Inspect local network interfaces')
    add_common(x)
    x.set_defaults(func=command_interfaces)
    x=sub.add_parser('diff',help='Compare two saved snapshots')
    add_common(x)
    x.add_argument('before')
    x.add_argument('after')
    x.add_argument('--limit',type=int,default=100)
    x.set_defaults(func=command_diff)
    x=sub.add_parser('report',help='Analyze a saved snapshot')
    add_common(x)
    x.add_argument('file')
    add_filter(x)
    x.set_defaults(func=command_report)
    x=sub.add_parser('watch',help='Monitor TCP connections and counters over time')
    add_common(x,False)
    x.add_argument('--interval',type=float,default=2.0)
    x.add_argument('--duration',type=float,default=0)
    x.add_argument('--count',type=int,default=0)
    x.add_argument('--jsonl')
    x.add_argument('--max-anomalies',type=int,default=20)
    x.set_defaults(func=command_watch)
    x=sub.add_parser('timeline',help='Analyze JSONL watch captures')
    add_common(x)
    x.add_argument('file')
    x.add_argument('--strict',action='store_true')
    x.set_defaults(func=command_timeline)
    x=sub.add_parser('export',help='Export snapshot list sections as CSV')
    x.add_argument('file')
    x.add_argument('--section',choices=['connections','tcp_stats','process_sockets','interfaces','routes','anomalies'],default='connections')
    x.add_argument('--output')
    x.set_defaults(func=command_export)
    add_extended_commands(sub)
    add_more_commands(sub)
    add_kernel_commands(sub)
    add_final_commands(sub)
    add_test_commands(sub)
    add_quick_command(sub)
    return p


def platform_warning():
    if not sys.platform.startswith('freebsd'):
        return 'Native collection commands require FreeBSD; offline analysis is portable'
    return None


def main(argv=None):
    args=parser().parse_args(argv)
    if hasattr(args,'timeout') and args.timeout<=0:
        raise ForensicsError('timeout must be positive')
    if hasattr(args,'interval') and args.interval<=0:
        raise ForensicsError('interval must be positive')
    try:
        return args.func(args)
    except (ForensicsError,OSError,ValueError,KeyError) as e:
        print('Error:',str(e),file=sys.stderr)
        return 2


if __name__=='__main__':
    sys.exit(main())
