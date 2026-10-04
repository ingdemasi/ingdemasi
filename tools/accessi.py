"""Gestione accessi alle aree riservate del sito (clienti e partner).
Uso:
  python3 tools/accessi.py add clienti CODICE "Nome" LINK_CARTELLA [LINK_UPLOAD]
  python3 tools/accessi.py add partner COMMESSA "Nome partner" LINK_CARTELLA [LINK_UPLOAD] [RUOLO] [PROGETTO]
  python3 tools/accessi.py del clienti CODICE | del partner COMMESSA "Nome partner"
Per i partner l'accesso e' per commessa: piu' partner sulla stessa commessa, ognuno con la sua password e la sua sottocartella.
  python3 tools/accessi.py list
'add' stampa la password generata (non viene salvata). I dati sono cifrati
(AES-GCM, chiave PBKDF2-SHA256 dalla password) in app/clienti.json e app/partner.json."""
import sys, json, os, base64, hashlib, secrets, pathlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
APP=pathlib.Path(__file__).resolve().parent.parent/'app'
KINDS={'clienti':('clienti.json','dm:'),'partner':('partner.json','dm-partner:')}
ITER=200000; ALPH='ABCDEFGHJKMNPQRSTUVWXYZ23456789'
def norm(c): return ''.join(c.strip().upper().split())
def path(k): return APP/KINDS[k][0]
def kid(k,c): return hashlib.sha256((KINDS[k][1]+norm(c)).encode()).hexdigest()
def loaddb(k): return json.load(open(path(k))) if path(k).exists() else {'v':1,'iter':ITER,'clients':{}}
def savedb(k,d): json.dump(d,open(path(k),'w'),indent=1,sort_keys=True)
def add(k,code,nome,link,upload='',ruolo='',progetto='',pw=None):
    pw=pw or ''.join(secrets.choice(ALPH) for _ in range(10))
    salt=os.urandom(16); iv=os.urandom(12)
    key=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,ITER,32)
    rec={'nome':nome,'link':link,'upload':upload}
    if k=='clienti': rec['commessa']=norm(code)
    else: rec.update({'ruolo':ruolo,'progetto':progetto,'commessa':norm(code)})
    ct=AESGCM(key).encrypt(iv,json.dumps(rec).encode(),None)
    entry={'s':base64.b64encode(salt).decode(),'i':base64.b64encode(iv).decode(),'d':base64.b64encode(ct).decode()}
    d=loaddb(k); h=kid(k,code)
    if k=='partner':
        lst=d['clients'].get(h,[]); lst=lst if isinstance(lst,list) else [lst]
        entry['n']=hashlib.sha256(nome.strip().lower().encode()).hexdigest()[:12]
        lst=[e for e in lst if e.get('n')!=entry['n']]+[entry]; d['clients'][h]=lst
    else: d['clients'][h]=entry
    savedb(k,d); return pw
def remove(k,code,nome=''):
    d=loaddb(k); h=kid(k,code)
    if k=='partner' and nome:
        n=hashlib.sha256(nome.strip().lower().encode()).hexdigest()[:12]
        lst=[e for e in d['clients'].get(h,[]) if e.get('n')!=n]
        if lst: d['clients'][h]=lst
        else: d['clients'].pop(h,None)
    else: d['clients'].pop(h,None)
    savedb(k,d)
if __name__=='__main__':
    a=sys.argv[1:]
    if a[:1]==['add']: print(add(*a[1:]))
    elif a[:1]==['del']: remove(*a[1:])
    else: [print(k,sum(len(v) if isinstance(v,list) else 1 for v in loaddb(k)['clients'].values())) for k in KINDS]
