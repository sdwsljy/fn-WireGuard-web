#!/bin/sh
cat <<'EOF'
Content-Type: text/html

<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireGuard 管理器 - 入口检测</title>
<style>
body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#0a0f1a;color:#e6edf7}
.box{max-width:760px;margin:54px auto;padding:28px;background:#0f1828;border:1px solid #1d2b44;border-radius:14px;box-shadow:0 18px 50px rgba(0,0,0,.35)}
h1{font-size:20px;margin:0 0 14px;color:#e6edf7}
p{color:#8b9bb4;line-height:1.7}
.status{margin-top:18px;padding:12px 14px;border-radius:10px;background:#121d30;border-left:3px solid #2dd4a7;color:#a8f3dd}
a{color:#2dd4a7}
</style>
<script>
function params(){
  var out={}, q=(location.search||'').replace(/^\?/,'');
  q.split('&').forEach(function(pair){
    if(!pair)return;
    var i=pair.indexOf('='), k=i>=0?pair.slice(0,i):pair, v=i>=0?pair.slice(i+1):'';
    out[decodeURIComponent(k)] = decodeURIComponent(v);
  });
  return out;
}
function build(){
  var p=params(), host=location.hostname || location.host.split(':')[0], urls=[];
  for(var i=1;i<=2;i++){
    var proto=(p['uH'+i]||'http').replace(/:\/\//g,'').replace(/:/g,'').toLowerCase();
    if(proto!=='http' && proto!=='https') proto='http';
    var base=p['uB'+i]||'';
    if(!base && i===1) base='51821';
    if(!base) continue;
    if(/^\d+$/.test(base)) urls.push(proto+'://'+host+':'+base+'/');
    else if(/^\/\//.test(base)) urls.push(proto+':'+base);
    else if(/^https?:\/\//i.test(base)) urls.push(base);
    else if(base.charAt(0)==='/') urls.push(proto+'://'+location.host+base);
    else urls.push(proto+'://'+base);
  }
  return urls;
}
function reachable(url, timeout){
  return new Promise(function(resolve){
    var done=false, img=new Image(), sep=url.indexOf('?')>=0?'&':'?';
    var t=setTimeout(function(){ if(!done){done=true; resolve(false);} }, timeout||1200);
    img.onload=function(){ if(!done){done=true; clearTimeout(t); resolve(true);} };
    img.onerror=function(){ if(!done){done=true; clearTimeout(t); resolve(/^https?:\/\/(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(url));} };
    img.src=url+sep+'wgweb_ping='+Date.now();
  });
}
function go(){
  var urls=build(), s=document.getElementById('status');
  if(!urls.length){s.innerHTML='未检测到可跳转地址，请使用外部访问：<code>http://NAS_IP:51821/</code>';return;}
  if(urls.length===1){s.textContent='正在跳转：'+urls[0]; location.replace(urls[0]); return;}
  s.textContent='正在检测：'+urls[0];
  reachable(urls[0],1000).then(function(ok){
    var target=ok?urls[0]:urls[1];
    s.textContent='正在跳转：'+target;
    location.replace(target);
  });
}
window.onload=go;
</script>
</head>
<body>
<div class="box">
  <h1>WireGuard 管理器</h1>
  <p>正在检测可访问的管理入口。若长时间没有跳转，请直接访问 <code>http://NAS_IP:51821/</code>。</p>
  <div id="status" class="status">准备检测...</div>
</div>
</body>
</html>
EOF
