"""Gestione accessi Area clienti.
Uso: python3 clienti.py add CODICE "Nome" LINK_CARTELLA [LINK_UPLOAD]   -> stampa la password
     python3 clienti.py del CODICE
     python3 clienti.py list
Scrive /home/claude/ingdemasi/app/clienti.json (dati cifrati, nessuna password salvata)."""
import sys, json, os, base64, hashlib, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pathlib; DB=str(pathlib.Path(__file__).resolve().parent.parent/'app'/'clienti.json'); ITER=200000
ALPH='ABCDEFGHJKMNPQRSTUVWXYZ23456789'
def norm(c): return ''.join(c.strip().upper().split())
def kid(c): return hashlib.sha256(('dm:'+norm(c)).encode()).hexdigest()
def loaddb(): return json.load(open(DB)) if os.path.exists(DB) else {'v':1,'iter':ITER,'clients':{}}
def savedb(d): json.dump(d,open(DB,'w'),indent=1,sort_keys=True)
def add(code,nome,link,upload='',pw=None):
    pw=pw or ''.join(secrets.choice(ALPH) for _ in range(10))
    salt=os.urandom(16); iv=os.urandom(12)
    key=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,ITER,32)
    data=json.dumps({'nome':nome,'commessa':norm(code),'link':link,'upload':upload}).encode()
    ct=AESGCM(key).encrypt(iv,data,None)
    d=loaddb(); d['clients'][kid(code)]={'s':base64.b64encode(salt).decode(),'i':base64.b64encode(iv).decode(),'d':base64.b64encode(ct).decode()}
    savedb(d); return pw
if __name__=='__main__':
    a=sys.argv[1:]
    if a and a[0]=='add': print(add(*a[1:]))
    elif a and a[0]=='del': d=loaddb(); d['clients'].pop(kid(a[1]),None); savedb(d)
    else: print(len(loaddb()['clients']),'clienti')
