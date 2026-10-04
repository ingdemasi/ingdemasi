"""Gestione accessi alle aree riservate del sito (clienti e partner).
Uso:
  python3 tools/accessi.py add clienti CODICE "Nome" LINK_CARTELLA [LINK_UPLOAD]
  python3 tools/accessi.py add partner CODICE "Nome" LINK_CARTELLA [LINK_UPLOAD] [RUOLO]
  python3 tools/accessi.py del clienti|partner CODICE
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
def add(k,code,nome,link,upload='',ruolo='',pw=None):
    pw=pw or ''.join(secrets.choice(ALPH) for _ in range(10))
    salt=os.urandom(16); iv=os.urandom(12)
    key=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,ITER,32)
    rec={'nome':nome,'link':link,'upload':upload}
    if k=='clienti': rec['commessa']=norm(code)
    else: rec['ruolo']=ruolo
    ct=AESGCM(key).encrypt(iv,json.dumps(rec).encode(),None)
    d=loaddb(k); d['clients'][kid(k,code)]={'s':base64.b64encode(salt).decode(),'i':base64.b64encode(iv).decode(),'d':base64.b64encode(ct).decode()}
    savedb(k,d); return pw
if __name__=='__main__':
    a=sys.argv[1:]
    if a[:1]==['add']: print(add(*a[1:]))
    elif a[:1]==['del']: d=loaddb(a[1]); d['clients'].pop(kid(a[1],a[2]),None); savedb(a[1],d)
    else: [print(k,len(loaddb(k)['clients'])) for k in KINDS]
