/* Aree riservate (clienti e partner) — accesso con codice e password.
   I dati di ogni utente (nome e link alla cartella) sono cifrati in clienti.json / partner.json
   con AES-GCM; la chiave si ricava dalla password (PBKDF2-SHA256), quindi senza
   password non sono leggibili. Nessun dato viene inviato a server esterni. */
(function(){
  var ROOT=document.currentScript.src.replace(/auth\.js(\?.*)?$/,'');
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
    '.dm-auth a.dm-out{font-size:.88rem}'+
    '.dm-auth .dm-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.dm-auth .dm-row .dm-btn{margin-top:10px}'+
    '.dm-auth .dm-wa{background:#1f7a4d;border-color:#1f7a4d;color:#fff}'+
    '.dm-auth textarea{width:100%;min-height:90px;font:inherit;color:var(--ink);background:var(--paper);border:1.5px solid var(--rule);padding:10px 12px;border-radius:0;resize:vertical}'+
    '.dm-auth hr{border:0;border-top:1px solid var(--rule);margin:18px 0 4px}';
  var st=document.createElement('style');st.textContent=css;document.head.appendChild(st);

  var PHONE='393939056385',EMAIL='studio@ingdemasi.com';
  var KINDS={
    clienti:{db:'clienti.json',key:'dm-area-clienti',salt:'dm:',title:'Accedi alla tua pratica',codeLabel:'Codice cliente',codePh:'Es. 017-26',
      who:function(s){return s.nome?('Pratica di '+s.nome):'La tua pratica';},sub:function(s){return s.commessa?('Commessa '+s.commessa):'';},
      ok:'Documenti, elaborati e aggiornamenti della tua pratica sono nella tua cartella riservata.',open:'Apri la mia cartella',up:'Carica documenti per lo studio',
      help:'Codice e password te li comunica lo studio all’avvio della pratica. Li hai persi? Scrivimi o chiamami.',actions:false},
    partner:{db:'partner.json',key:'dm-area-partner',salt:'dm-partner:',title:'Accesso partner',codeLabel:'Codice partner',codePh:'Es. PA-001',
      who:function(s){return s.nome||'Area partner';},sub:function(s){return s.ruolo||'';},
      ok:'Nella cartella condivisa trovi elaborati, documenti e materiale di lavoro dei progetti in comune.',open:'Apri la cartella condivisa',up:'Carica file per lo studio',
      help:'Le credenziali di accesso te le fornisce lo studio. Problemi di accesso? Scrivimi o chiamami.',actions:true}
  };
  function save(K,v){try{if(v)localStorage.setItem(K.key,JSON.stringify(v));else localStorage.removeItem(K.key);}catch(e){}}
  function load(K){try{return JSON.parse(localStorage.getItem(K.key)||'null');}catch(e){return null;}}
  function b64(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
  function hex(buf){return [].map.call(new Uint8Array(buf),function(x){return ('0'+x.toString(16)).slice(-2);}).join('');}
  function norm(c){return (c||'').trim().toUpperCase().replace(/\s+/g,'');}
  function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
  function safeUrl(u){try{var x=new URL(u);return x.protocol==='https:'&&/(^|\.)dropbox\.com$/.test(x.hostname)?x.href:'';}catch(e){return '';}}

  function unlock(K,code,pass){
    if(!window.crypto||!crypto.subtle)return Promise.reject(new Error('browser'));
    var enc=new TextEncoder();
    return Promise.all([
      fetch(ROOT+K.db,{cache:'no-cache'}).then(function(r){if(!r.ok)throw new Error('rete');return r.json();}),
      crypto.subtle.digest('SHA-256',enc.encode(K.salt+norm(code)))
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

  function actionsHtml(id){
    return '<hr><div class="label" style="margin-top:12px">Contatta lo studio</div>'+
      '<label for="'+id+'t">Tipo di richiesta</label>'+
      '<select id="'+id+'t" style="width:100%;font:inherit;color:var(--ink);background:var(--paper);border:1.5px solid var(--rule);padding:10px 12px;border-radius:0">'+
      '<option>Richiesta di incontro</option><option>Domanda tecnica</option><option>Aggiornamento su un progetto</option></select>'+
      '<label for="'+id+'m">Messaggio</label><textarea id="'+id+'m" placeholder="Progetto, giorno preferito, domanda…"></textarea>'+
      '<div class="dm-row"><button type="button" class="dm-btn dm-wa" data-ch="wa">WhatsApp</button><button type="button" class="dm-btn" data-ch="mail">Email</button></div>'+
      '<p class="dm-hint dm-sent" role="status"></p>';
  }

  function render(box){
    var K=KINDS[box.hasAttribute('data-area-partner')?'partner':'clienti'];
    var s=load(K);
    if(s&&safeUrl(s.link)){
      var up=safeUrl(s.upload||''),id='dm'+Math.random().toString(36).slice(2,7),sub=K.sub(s);
      box.innerHTML='<div class="dm-auth">'+
        '<div class="label">Area riservata</div><h3>'+esc(K.who(s))+'</h3>'+
        (sub?'<div class="dm-hint" style="margin:0 0 6px">'+esc(sub)+'</div>':'')+
        '<div class="dm-ok"><i></i><span>'+K.ok+'</span></div>'+
        '<a class="dm-btn dm-primary" href="'+esc(safeUrl(s.link))+'" target="_blank" rel="noopener">'+K.open+'</a>'+
        (up?'<a class="dm-btn" href="'+esc(up)+'" target="_blank" rel="noopener">'+K.up+'</a>':'')+
        (K.actions?actionsHtml(id):'')+
        '<p class="dm-hint">Accesso salvato su questo dispositivo. <a href="#" class="dm-out">Esci</a></p></div>';
      box.querySelector('.dm-out').addEventListener('click',function(e){e.preventDefault();save(K,null);render(box);});
      if(K.actions){
        box.querySelector('.dm-row').addEventListener('click',function(e){
          var b=e.target.closest('[data-ch]');if(!b)return;
          var tipo=box.querySelector('#'+id+'t').value,m=box.querySelector('#'+id+'m').value.trim(),out=box.querySelector('.dm-sent');
          if(!m){out.textContent='Scrivi il messaggio.';return;}
          var subj=tipo+' – '+(s.nome||'partner'),body=['Da: '+(s.nome||'')+(s.ruolo?(' ('+s.ruolo+')'):''),'',m].join('\n');
          if(b.dataset.ch==='wa')window.open('https://wa.me/'+PHONE+'?text='+encodeURIComponent(subj+'\n'+body),'_blank','noopener');
          else location.href='mailto:'+EMAIL+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body);
          out.textContent='Si è aperta l’app per l’invio: controlla e premi Invia.';
        });
      }
      box.dispatchEvent(new CustomEvent('dm-login',{bubbles:true,detail:s}));
      return;
    }
    var id2='dm'+Math.random().toString(36).slice(2,7);
    box.innerHTML='<form class="dm-auth" novalidate>'+
      '<div class="label">Area riservata</div><h3>'+K.title+'</h3>'+
      '<label for="'+id2+'c">'+K.codeLabel+'</label><input id="'+id2+'c" autocomplete="username" autocapitalize="characters" placeholder="'+K.codePh+'" required>'+
      '<label for="'+id2+'p">Password</label><input id="'+id2+'p" type="password" autocomplete="current-password" required>'+
      '<label class="dm-check"><input type="checkbox" checked> Ricordami su questo dispositivo</label>'+
      '<button class="dm-btn dm-primary" type="submit">Accedi</button>'+
      '<p class="dm-msg" role="alert"></p>'+
      '<p class="dm-hint">'+K.help+'</p></form>';
    box.dispatchEvent(new CustomEvent('dm-logout',{bubbles:true}));
    var f=box.querySelector('form'),msg=f.querySelector('.dm-msg'),btn=f.querySelector('button');
    f.addEventListener('submit',function(e){
      e.preventDefault();
      var c=f.querySelector('#'+id2+'c').value,p=f.querySelector('#'+id2+'p').value,rem=f.querySelector('.dm-check input').checked;
      if(!c||!p){msg.textContent='Inserisci codice e password.';return;}
      btn.disabled=true;btn.textContent='Verifica in corso…';msg.textContent='';
      unlock(K,c,p).then(function(d){
        d.commessa=d.commessa||norm(c);
        if(rem){save(K,d);render(box);}
        else{var prev=load(K);save(K,d);render(box);save(K,prev);}
      }).catch(function(err){
        btn.disabled=false;btn.textContent='Accedi';
        msg.textContent=err.message==='cred'?'Codice o password non corretti.':err.message==='browser'?'Il tuo browser non supporta l’accesso sicuro: aggiornalo.':'Connessione non disponibile, riprova.';
      });
    });
  }
  window.DMAreaRiservata={mount:function(el){if(el)render(el);}};
  function auto(){[].forEach.call(document.querySelectorAll('[data-area-clienti],[data-area-partner]'),render);}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',auto);else setTimeout(auto,0);
})();
