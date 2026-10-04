/* Area clienti — accesso con codice cliente e password.
   I dati di ogni cliente (nome e link alla cartella) sono cifrati in clienti.json
   con AES-GCM; la chiave si ricava dalla password (PBKDF2-SHA256), quindi senza
   password non sono leggibili. Nessun dato viene inviato a server esterni. */
(function(){
  var ROOT=document.currentScript.src.replace(/auth\.js(\?.*)?$/,'');
  var KEY='dm-area-clienti';
  var css='.dm-auth label{display:block;font-weight:500;font-size:.92rem;margin:12px 0 4px}'+
    '.dm-auth input{width:100%;font:inherit;color:var(--ink);background:var(--paper);border:1.5px solid var(--rule);padding:10px 12px;border-radius:0}'+
    '.dm-auth input:focus{outline:2px solid var(--accent);outline-offset:0;border-color:var(--accent)}'+
    '.dm-auth .dm-btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:48px;margin-top:14px;padding:10px 16px;border:1.5px solid var(--ink);background:var(--sheet);color:var(--ink);font-family:inherit;font-size:1rem;font-weight:600;text-decoration:none;cursor:pointer}'+
    '.dm-auth .dm-btn.dm-primary{background:var(--accent);border-color:var(--accent);color:#fff}'+
    '.dm-auth .dm-btn[disabled]{opacity:.6;cursor:wait}'+
    '.dm-auth .dm-check{display:flex;align-items:center;gap:8px;font-weight:400;margin-top:12px}'+
    '.dm-auth .dm-check input{width:auto}'+
    '.dm-auth .dm-msg{min-height:1.4em;margin:10px 0 0;font-size:.9rem;color:var(--warn,#b8432f)}'+
    '.dm-auth .dm-hint{font-size:.85rem;color:var(--muted);margin:10px 0 0}'+
    '.dm-auth .dm-ok{display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--accent-soft);font-size:.92rem;margin:8px 0 4px}'+
    '.dm-auth .dm-ok i{width:10px;height:10px;border-radius:50%;background:var(--accent);flex:none}'+
    '.dm-auth h3{font-family:var(--display);font-size:1.5rem;margin:2px 0 6px;line-height:1.05}'+
    '.dm-auth a.dm-out{font-size:.88rem}';
  var st=document.createElement('style');st.textContent=css;document.head.appendChild(st);

  function b64(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
  function hex(buf){return [].map.call(new Uint8Array(buf),function(x){return ('0'+x.toString(16)).slice(-2);}).join('');}
  function norm(c){return (c||'').trim().toUpperCase().replace(/\s+/g,'');}
  function save(v){try{if(v)localStorage.setItem(KEY,JSON.stringify(v));else localStorage.removeItem(KEY);}catch(e){}}
  function load(){try{return JSON.parse(localStorage.getItem(KEY)||'null');}catch(e){return null;}}
  function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
  function safeUrl(u){try{var x=new URL(u);return x.protocol==='https:'&&/(^|\.)dropbox\.com$/.test(x.hostname)?x.href:'';}catch(e){return '';}}

  function unlock(code,pass){
    if(!window.crypto||!crypto.subtle)return Promise.reject(new Error('browser'));
    var enc=new TextEncoder();
    return Promise.all([
      fetch(ROOT+'clienti.json',{cache:'no-cache'}).then(function(r){if(!r.ok)throw new Error('rete');return r.json();}),
      crypto.subtle.digest('SHA-256',enc.encode('dm:'+norm(code)))
    ]).then(function(res){
      var db=res[0],rec=db.clients&&db.clients[hex(res[1])];
      if(!rec)throw new Error('cred');
      return crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']).then(function(base){
        return crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(rec.s),iterations:db.iter||200000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
      }).then(function(key){
        return crypto.subtle.decrypt({name:'AES-GCM',iv:b64(rec.i)},key,b64(rec.d));
      }).then(function(plain){return JSON.parse(new TextDecoder().decode(plain));},function(){throw new Error('cred');});
    });
  }

  function render(box){
    var s=load();
    if(s&&safeUrl(s.link)){
      var up=safeUrl(s.upload||'');
      box.innerHTML='<div class="dm-auth">'+
        '<div class="label">Area riservata</div><h3>'+esc(s.nome?('Pratica di '+s.nome):'La tua pratica')+'</h3>'+
        (s.commessa?'<div class="dm-hint" style="margin:0 0 6px">Commessa '+esc(s.commessa)+'</div>':'')+
        '<div class="dm-ok"><i></i><span>Documenti, elaborati e aggiornamenti della tua pratica sono nella tua cartella riservata.</span></div>'+
        '<a class="dm-btn dm-primary" href="'+esc(safeUrl(s.link))+'" target="_blank" rel="noopener">Apri la mia cartella</a>'+
        (up?'<a class="dm-btn" href="'+esc(up)+'" target="_blank" rel="noopener">Carica documenti per lo studio</a>':'')+
        '<p class="dm-hint">Accesso salvato su questo dispositivo. <a href="#" class="dm-out">Esci</a></p></div>';
      box.querySelector('.dm-out').addEventListener('click',function(e){e.preventDefault();save(null);render(box);});
      box.dispatchEvent(new CustomEvent('dm-login',{bubbles:true,detail:s}));
      return;
    }
    var id='dm'+Math.random().toString(36).slice(2,7);
    box.innerHTML='<form class="dm-auth" novalidate>'+
      '<div class="label">Area riservata</div><h3>Accedi alla tua pratica</h3>'+
      '<label for="'+id+'c">Codice cliente</label><input id="'+id+'c" autocomplete="username" autocapitalize="characters" placeholder="Es. 017-26" required>'+
      '<label for="'+id+'p">Password</label><input id="'+id+'p" type="password" autocomplete="current-password" required>'+
      '<label class="dm-check"><input type="checkbox" checked> Ricordami su questo dispositivo</label>'+
      '<button class="dm-btn dm-primary" type="submit">Accedi</button>'+
      '<p class="dm-msg" role="alert"></p>'+
      '<p class="dm-hint">Codice e password te li comunica lo studio all’avvio della pratica. Li hai persi? Scrivimi o chiamami.</p></form>';
    box.dispatchEvent(new CustomEvent('dm-logout',{bubbles:true}));
    var f=box.querySelector('form'),msg=f.querySelector('.dm-msg'),btn=f.querySelector('button');
    f.addEventListener('submit',function(e){
      e.preventDefault();
      var c=f.querySelector('#'+id+'c').value,p=f.querySelector('#'+id+'p').value,rem=f.querySelector('.dm-check input').checked;
      if(!c||!p){msg.textContent='Inserisci codice e password.';return;}
      btn.disabled=true;btn.textContent='Verifica in corso…';msg.textContent='';
      unlock(c,p).then(function(d){
        d.commessa=d.commessa||norm(c);
        if(rem)save(d);else{try{sessionStorage.setItem(KEY,JSON.stringify(d));}catch(_){}}
        if(!rem){ /* sessione solo per questa visita */
          var ls=load();save(d);render(box);save(ls);return;}
        render(box);
      }).catch(function(err){
        btn.disabled=false;btn.textContent='Accedi';
        msg.textContent=err.message==='cred'?'Codice o password non corretti.':err.message==='browser'?'Il tuo browser non supporta l’accesso sicuro: aggiornalo.':'Connessione non disponibile, riprova.';
      });
    });
  }
  window.DMAreaClienti={mount:function(el){if(el)render(el);}};
  function auto(){[].forEach.call(document.querySelectorAll('[data-area-clienti]'),render);}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',auto);else setTimeout(auto,0);
})();
