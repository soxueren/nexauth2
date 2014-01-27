
/*
 *  NexAuth 2 client library
 *  (c) 2012 Nexhawks
 */

function copy_undef_properties(src, dest)
{
    for (var prop in src) {
        if (typeof(dest[prop]) == "undefined") {
            dest[prop] = src[prop];
        }
    }
}

function inherit(subClass, superClass)
{
    copy_undef_properties(superClass.prototype, subClass.prototype);
}


/*
 * Some hacks to cryptico.js to make it faster
 */
aes.Encrypt = function(block, key){
    var l = key.length;
    aes.AddRoundKey(block, key, 0);
    for (var i = 16; i < l - 16; i += 16) {
        aes.SubBytes(block, aes.Sbox);
        aes.ShiftRows(block, aes.ShiftRowTab);
        aes.MixColumns(block);
        aes.AddRoundKey(block, key, i);
    }
    aes.SubBytes(block, aes.Sbox);
    aes.ShiftRows(block, aes.ShiftRowTab);
    aes.AddRoundKey(block, key, i);
};
aes.Decrypt = function (block, key) {
    var l = key.length;
    aes.AddRoundKey(block, key, l - 16);
    aes.ShiftRows(block, aes.ShiftRowTab_Inv);
    aes.SubBytes(block, aes.Sbox_Inv);
    for (var i = l - 32; i >= 16; i -= 16) {
        aes.AddRoundKey(block, key, i);
        aes.MixColumns_Inv(block);
        aes.ShiftRows(block, aes.ShiftRowTab_Inv);
        aes.SubBytes(block, aes.Sbox_Inv);
    }
    aes.AddRoundKey(block, key, 0);
};
aes.ShiftRows = function(state, shifttab){
    // my.ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
    // this way is up to 10x faster!
    var s01 = state[1], s02 = state[2], s03 = state[3];
    var s05 = state[5], s06 = state[6], s07 = state[7];
    var s09 = state[9], s10 = state[10], s11 = state[11];
    var s13 = state[13], s14 = state[14], s15 = state[15];
    if(shifttab[1] == 5){
        // encrypt
        state[1] = s05; state[2] = s10; state[3] = s15;
        state[5] = s09; state[6] = s14; state[7] = s03;
        state[9] = s13; state[10] = s02; state[11] = s07;
        state[13] = s01; state[14] = s06; state[15] = s11;
    }else{
        // decrypt
        state[5] = s01; state[10] = s02; state[15] = s03;
        state[9] = s05; state[14] = s06; state[3] = s07;
        state[13] = s09; state[2] = s10; state[7] = s11;
        state[1] = s13; state[6] = s14; state[11] = s15;
    }
};
aes.AddRoundKey = function(state, rkey, index){
    // this version eliminates Array#slice
    for (var i = 0; i < 16; i++)
        state[i] ^= rkey[i + index];
};

/* ---- NASession ---- 
 
    low-level interface for NexAuth protocol client.
   
 */

function NASession(){
	this.endpoint = null;
	this.state = 'NotConnected';
	this.cmdReq = []
}
NASession.prototype = {
connect: function(endpoint, callback){
	if(this.state != 'NotConnected'){
		return;
	}
	this.endpoint = endpoint;
	this.state = 'Connecting';
	
	var req = NACreateXHR();
	var session = this;
	req.onreadystatechange = function(){
		try{
			if(this.readyState == 4){ // Done
				session.state = 'NotConnected';
				if(this.status == 200){
					var resp = this.responseText;
					resp = session.parseResponse(resp)
					if(resp.type=='PublicKey'){
						var keyStr = resp.key;
						matches = keyStr.match(/([0-9]+):([^:]*):([^:]*)/);
						if(matches.length == 0){
							callback(false, "invalid response - not valid key");
						}else{
							timeStr = matches[1];
							keyStr = matches[2];
							salt = matches[3];
							
							session.rsaKey = new RSAKey();
							session.rsaKey.setPublic(keyStr, "10001");
							//alert("key length = "+keyStr.length);
							
							session.rsaServerTime = parseFloat(timeStr);
							session.rsaLocalTime = new Date();
							
							session.state = 'NotAuthorized';
							
							try{
								callback(true, salt);
							}catch(e){
								// if callback(true,...) throws an error,
								// it may cause callback to be called again with
								// argument false.
								return;
							}
						}
						
					}else if(resp.type=='Error'){
						throw(resp.message);
					}else{
						throw("invalid response");
					}
				}else{
					throw("network error: "+String(this.status)+" "+this.statusText);
				}
			}
		}catch(e){
			callback(false, e);
		}
		
	};
	//console.debug("POSTing to"+this.endpoint);
	this.connReq = req;
	req.open("POST", this.endpoint, false); // strangely asnyc doesn't works...
	req.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
	req.send("QPBK"+String(Math.random())+String(Math.random())+"\r\n");
	//console.debug("postend to"+this.endpoint);
},
disconnect:function(){
	//console.debug("disconnect");
	this.abort();
	this.connReq = null;
	this.authReq = null;
	this.cmdReq = [];
	this.state = 'NotConnected';
},
abort:function(){
	//console.debug("abort");
	if(this.state == 'Connecting'){
		this.connReq.onreadystatechange=function(){}
		this.connReq.abort();
		this.connReq = null;
		this.state = 'NotConnected';
	}else if(this.state == 'Authorizing'){
		this.authReq.onreadystatechange=function(){}
		this.authReq.abort();
		this.authReq = null;
		this.state = 'NotAuthorized';
	}
	
	for(var i in this.cmdReq){
		var req = this.cmdReq[i];
		req.onreadystatechange=function(){}
		req.abort();
	}
	this.cmdReq = [];
	
},
authorize:function(identity, callback){
	if(this.state == 'NotConnected'){
		throw "not yet connected.";
	}
	
	this.aesKey = NAGenerateAESKey();
	this.expandedAesKey = this.aesKey.slice(0);
	aes.ExpandKey(this.expandedAesKey);
	this.state = 'Authorizing';
	this.seq = 1;
	
	if(typeof(identity)=='string')
		identity=NABytesFromString(identity);
	
	if(typeof(identity)!='object')
		throw "invalid identity data type: "+typeof(identity)+".";
	
	if(identity.length > 255){
		throw "identity too long.";
	}
	
	
	// add identity
	var bytes = NABytesFromString("!auth");

	// add timestamp.
	var timeStr = String(parseInt(this.currentRsaServerTime()));
	var timeBytes = NABytesFromString(timeStr);
	if(timeBytes.length > 255){
		throw "time too big(BUG?)"
	}

	// add aes key
	var key = this.aesKey;
	
	bytes = bytes.concat(NAImplodeChunk([identity, timeBytes, key]));
	var str = NAEncodeBase64(bytes);
	
	var encrypted = this.rsaKey.encrypt(str);
	//alert("encrypted length = "+encrypted.length )
	
	var req = NACreateXHR();
	var session = this;
	req.onreadystatechange = function(){
		try{
			if(this.readyState == 4){ // Done
				session.state = 'NotAuthorized';
				if(this.status == 200){
					var resp = this.responseText;
					resp = session.parseResponse(resp)
					if(resp.type=='Accepted'){
						session.state = 'Connected';
						session.sessionId = resp.sessionId;
						session.sessionIdStr = NAStringFromBytes(resp.sessionId);
						callback(true, NAStringFromBytes(resp.message))
					}else if(resp.type=='Error'){
						throw(resp.message);
					}else{
						throw("invalid response");
					}
				}else{
					throw("network error: "+String(this.status)+" "+this.statusText);
				}
			}
		}catch(e){
			callback(false, e);
		}
		
	}
	
	this.authReq = req;
	req.open("POST", this.endpoint, false);
	req.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
	req.send("QATH|" + encrypted+"|");

},

	
command:function(cmd, obj, callback){
	if(this.state != 'Connected'){
		throw "not yet connected or authorized.";
	}
	
	if(!obj)
		obj = null;
	
	// build command chunk.
	var cmdChunks = [this.sessionId,
					 NABytesFromString(String(this.seq)),
					 NABytesFromString(cmd),
					 NABytesFromString(JSON.stringify(obj))];
	var bytes = NAImplodeChunk(cmdChunks);
	this.seq+=1;
	
	bytes = NABytesFromString('!cmd').concat(bytes);
	
	// encrypt
	data = this.aesEncrypt(bytes);
	
	// add session id
	cmdStr = this.sessionIdStr + ":" + data;
	
	var req = NACreateXHR();
	var session = this;
	req.onreadystatechange = function(){
		try{
			if(this.readyState == 4){ // Done
				
				var cmdI = null;
				for(var i in session.cmdReq){
					if(session.cmdReq[i] == this){
						cmdI = i;
					}
				}
				if(cmdI){
					var reqs = session.cmdReq;
					reqs = reqs.slice(0, cmdI).concat(reqs.slice(cmdI+1));
					session.cmdReq = reqs;
				}
				
				if(this.status == 200){
					var resp = this.responseText;
					resp = session.parseResponse(resp)
					if(resp.type=='Result'){
						if(NAStringFromBytes(resp.sessionId)!=session.sessionIdStr){
							throw("result session id differs");
						}
						
						var obj = JSON.parse(NAStringFromBytes(resp.chunks[0]));
						if((typeof obj == 'object') && obj && obj._error){
							var err = obj._error;
							if(err.message){
								throw(err.message);
							}else{
								throw("unknown error (encrypted)");
							}
						}
						
						callback(true, obj);
					}else if(resp.type=='Error'){
						throw(resp.message);
					}else{
						throw("invalid response");
					}
				}else{
					throw("network error: "+String(this.status)+" "+this.statusText);
				}
			}
		}catch(e){
			callback(false, e);
		}
		
	}
	
	this.cmdReq.push(req);
	req.open('POST', this.endpoint, false);
	req.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
	req.send('QCOM' + cmdStr);
	
},
	
	
	
currentRsaServerTime:function(){
	var localDate = new Date();
	var localDateRef = this.rsaLocalTime;
	
	var diff = localDate.getTime() - localDateRef.getTime();
	
	return this.rsaServerTime + diff/1000;
},
	
	
parseResponse:function(rep){
	var type = rep.substr(0,4);
	var body = rep.substr(4);
	if(type == 'RPBK'){
		return {
		type: 'PublicKey',
		key: body
		}
	}else if(type == 'RERR'){
		return {
		type: 'Error',
		message: body
		}
	}else if(type == 'RCON'){
		body = this.aesDecrypt(body);
		var sig = '!authorized-';
		var readSig = NAStringFromBytes(body.slice(0, sig.length));
		if(readSig != sig){
			throw "invalid accept signature: "+readSig;
		}
		
		var chunks = NAExplodeChunk(body.slice(sig.length));
		if(chunks.length < 2){
			throw "too few chunks received.";
		}
		
		return {
		type: 'Accepted',
		sessionId: chunks[0],
		message: chunks[1]
		}
	}else if(type == 'RRES'){
		body = this.aesDecrypt(body);
		var sig = '!res-';
		var readSig = NAStringFromBytes(body.slice(0, sig.length));
		if(readSig != sig){
			throw "invalid result signature: "+readSig;
		}
		
		var chunks = NAExplodeChunk(body.slice(sig.length));
		if(chunks.length < 2){
			throw "too few chunks received.";
		}
		
		return {
		type: 'Result',
		sessionId: chunks[0],
		seq: parseInt(NAStringFromBytes(chunks[1])),
		chunks: chunks.slice(2)
		}
	}else{
		throw "invalid response type: "+type;
	}
},
	
aesDecrypt:function(enc){
	var bytes = NADecodeBase64(enc);
	var outBytes = bytes.slice(16);
	var exkey = this.expandedAesKey;
	var blocks = bytes.length >> 4;
	
	for(var i = 1; i < blocks; i++)
	{
		var tempBlock = bytes.slice(i * 16, i * 16 + 16);
		var prevBlock = bytes.slice((i-1) * 16, (i-1) * 16 + 16);
		aes.Decrypt(tempBlock, exkey);
		tempBlock = cryptico.blockXOR(prevBlock, tempBlock);
        
        var base = (i - 1) * 16;
        for(var k = 0; k < 16; k++)
            outBytes[base + k] = tempBlock[k];
	}
	
	//alert(cryptico.decryptAESCBC(enc, this.aesKey));
	return cryptico.depad(outBytes);
},
	
pkcs5pad:function(bytes){
	var padBytes = 16-(bytes.length & 15);
	for(var i = 0;i<padBytes;i++)
		bytes.push(padBytes);
},
	
aesEncrypt:function(inBytes){
	var outBytes = cryptico.blockIV();
	var exkey = this.expandedAesKey;
	
	inBytes = inBytes.slice(0);
	this.pkcs5pad(inBytes);
	if(inBytes.length&15)
		throw "not paddinged";
	//inBytes = cryptico.pad16(inBytes);
	
	var blocks = inBytes.length >> 4;

    outBytes = outBytes.concat(inBytes);

	for(var i = 0; i < blocks; i++)
	{
		var tempBlock = inBytes.slice(i * 16, i * 16 + 16);
		var prevBlock = outBytes.slice((i) * 16, (i) * 16 + 16);
		tempBlock = cryptico.blockXOR(prevBlock, tempBlock);
		aes.Encrypt(tempBlock, exkey);
        
        var base = (i + 1) * 16;
        for(var k = 0; k < 16; k++)
            outBytes[k + base] = tempBlock[k];
	}
	
	return NAEncodeBase64(outBytes);
}
};

var NAProxyManager = (function(){
    var my = {};
    
    var proxies = {};
    var nextId = 1;
    var reqs = {};
    
    var msgKey = String(Math.floor(Math.random()*99999.));
    msgKey += String(Math.floor(Math.random()*99999.));
    msgKey += String(Math.floor(Math.random()*99999.));
    msgKey += String(Math.floor(Math.random()*99999.));
    
    function processPendingRequests(proxy){
        var pendings = proxy.pendings;
        var frame = proxy.frame;
        for(var i in pendings){
            var req = pendings[i];
            if(req.aborted)
                continue;
            
            var obj = {
                type: 'post',
                id: req.id,
                data: req.data
            };
            frame.contentWindow.postMessage(JSON.stringify(obj), '*');
            
        }
        proxy.pendings = [];
    }
    
    function gotMessage(event){
        var data = event.data;
        //console.log(data);
        if(data.substr(0, msgKey.length) != msgKey){
            return;
        }
        
        var obj = JSON.parse(data.substr(msgKey.length));
        var type = obj.type;
        
        if(type == 'readystate'){
            var id = obj.id;
            var xhr = obj.xhr;
            if(!reqs[id])
                return;
            var req = reqs[id];
            
            req.readyState = xhr.readyState;
            req.responseText = xhr.responseText;
            req.status = xhr.status;
            req.statusText = xhr.statusText;
            
            var cb = req.onreadystatechange;
            
            // call onreadystatechange
            if(cb){
                cb.apply(req);
            }
            
            if(req.readyState == 4){
                req.id = null;
                delete reqs[id];
            }
        }else if(type == 'ready'){
            var url = obj.url;
            if(!proxies[url]) // 'ready' from unknown proxy
                return;
            var proxy = proxies[url];
            if(proxy.ready)
                return;
            proxy.ready = true;
            
            // stop timeout timer
            window.clearTimeout(proxy.timeoutTimer);
            
            // process pending events
            processPendingRequests(proxy);
        }else if(type == 'error'){
            
        }
    }
    
    window.addEventListener("message", gotMessage, false);
    
    my.deleteProxy = function(url){
        var proxy = proxies[url];
        if(!proxy)
            return;
        proxy.frame.parentNode.removeChild(proxy.frame);    
        delete proxies[proxy.url];
    };
    
    my.createProxy = function(url){
        var frame = document.createElement("iframe");
        frame.style.display = "none";
        frame.style.width = "1px";
        frame.style.height = "1px";
        frame.style.position = "absolute";
        frame.style.left = "-1px";
        frame.style.top = "-1px";
        document.body.appendChild(frame);
        
        var proxy = {
            frame: frame,
            url: url,
            ready: false,
            pendings: [],
            lastUsage: new Date().getTime()
        };
        
        var onConnectError = function(msg){
            if(!proxies[proxy.url])
                return;
            
            
            var pendings = proxy.pendings;
            for(var i in pendings){
                var req = pendings[i];
                if(req.aborted)
                    continue;
                req.protocolError(msg);
            }
            proxy.pendings = [];
            
            my.deleteProxy(proxy.url);
        }
        
        proxy.timeoutTimer = window.setTimeout(function(){
            if(proxy.ready)
                return;
            // proxy connection timeout
            onConnectError("Proxy connection timed out.");
        }, 10000);
        
        var onLoaded = function(){
            // iframe's onload
            if(!proxies[proxy.url])
                return;
            
            // initialize connection to the proxy
            var obj = {
                type: 'init',
                msgKey: msgKey,
                url: proxy.url
            };
            frame.contentWindow.postMessage(JSON.stringify(obj), '*');
            
        };
        
        if(document.all){
            frame.onreadystatechange = function(){
                if(frame.readyState == "complete"){
                    onLoaded();
                    this.onreadystatechange = null;
                }
            };
        }else{
            frame.onload = onLoaded;
        }
        
        frame.src = proxy.url;
        
        return proxy;
    };
    
    
    
    my.addRequest = function(req){ // NAProxyRequest
        var proxy = proxies[req.url];
        if(!proxy){
            proxy = my.createProxy(req.url);
            proxies[req.url] = proxy;
        }
        
        req.id = nextId;
        nextId += 1;
        reqs[req.id] = req;
        
        proxy.pendings.push(req);
        if(proxy.ready){
            processPendingRequests(proxy);
        }
    };
    
    my.abortRequest = function(req){
        req.aborted = true;
        if(!req.id) return;
        var proxy = proxies[req.url];
        if(!proxy) return;
        if(proxy.ready){
            // request is already sent, so we have to abort it
            var frame = proxy.frame;
            var obj = {
                type: 'abort',
                id: req.id
            };
            frame.contentWindow.postMessage(JSON.stringify(obj), '*');
        }
    }
    
    return my;
})();

function NAProxyRequest(){
    this.aborted = false;
    this.sent = false;
    this.id = null;
    this.onreadystatechange = null;
}
NAProxyRequest.prototype.open = function(method, url){
    this.url = url;
    if(method != 'POST')
        throw "Only POST supported by NexAuth proxy";
    
};
NAProxyRequest.prototype.protocolError = function(msg){
    var cb = this.onreadystatechange;
    this.status = 0;
    this.statusText = "NexAuth Proxy protocol error: "+msg;
    this.readyState = 4;
    this.responseText = msg;
    if(cb){
        cb.apply(this);
    }
};
NAProxyRequest.prototype.send = function(data){
    if(this.sent) return;
    this.data = data;
    this.sent = true;
    NAProxyManager.addRequest(this);
};
NAProxyRequest.prototype.abort = function(){
    if(!this.sent) return;
    if(this.aborted) return;
    NAProxyManager.abortRequest(this);
    this.aborted = true;
};
NAProxyRequest.prototype.setRequestHeader = function(name, value){
    
};

function NACreateXHR(uri){
    if((uri == null || uri.substr(0,0)=='/')){
        if(XMLHttpRequest){return new XMLHttpRequest()}
        if(ActiveXObject){
            var a="Msxml2.XMLHTTP.",b=[a+"6.0",a+"3.0","Microsoft.XMLHTTP"];
            for(var i=0;i<b.length;i++){try{return new ActiveXObject(b[i])}catch(e){}}
        }return false;
    }else{
        return new NAProxyRequest();
    }
}



function NAGenerateAESKey(){
	var bytes = []
	for(var i = 0; i < 16; i++){
		bytes.push(rng_get_byte());
	}
	return bytes;
}

function NABytesFromString(str){
	str = String(str);
	var bytes = [];
	var len = str.length;
	var i = 0;
	for (i = 0; i < len; i++){
		var c = str.charCodeAt(i);
		if(c<128){
			bytes.push(c);
		}else if(c>=128 && c<2048){
			bytes.push((c>>6) | 192);
			bytes.push((c&63) | 128);
		}else{
			bytes.push((c>>12)|224);
			bytes.push(((c>>6)&63)|128);
			bytes.push((c&63)|128);
		}
	}
	return bytes;
}

function NAStringFromBytes(bytes){
	var str = '';
	var i =0;
	while(i < bytes.length){
		if(bytes[i] < 128){
			str += String.fromCharCode(bytes[i]);
			i++;
		}else if(bytes[i] > 191 && bytes[i] < 224){
			if(i+1 >= bytes.length){
				str += String.fromCharCode(bytes[i]);
				i++;
				continue;
			}
			var c = bytes[i];
			var c2 = bytes[i+1];
			str += String.fromCharCode(((c&31)<<6)|(c2&63));
			i+=2;
		}else{
			if(i+2 >= bytes.length){
				str += String.fromCharCode(bytes[i]);
				i++;
				continue;
			}
			var c = bytes[i];
			var c2 = bytes[i+1];
			var c3 = bytes[i+2];
			str += String.fromCharCode(((c&15)<<12)|((c2&63)<<6)|(c3&63));
			i+=3;
		}
		
	}
	return str;
}

function NAExplodeChunk(bytes){
	var chunks = new Array();
	var i = 0;
	while(i < bytes.length){
		var siz = 0;
		var shift = 1;
		while(i < bytes.length){
			var v = bytes[i]; i+=1;
			if(v & 0x80){
				siz = (siz | ((v&0x7f) * shift));
				shift <<= 7;
			}else{
				siz |= v * shift;
				break;
			}
		}
	
		chunks.push(bytes.slice(i, i+siz));
		i+=siz;
	}
	return chunks;
}

function NAImplodeChunk(chunks){
	var bytes = new Array();
	for(var i in chunks){
		var chunk = chunks[i];
		var size = chunk.length;
		while(true){
			if(size >= 0x80){
				var v = size & 0x7f;
				bytes.push(v | 0x80);
				size >>= 7;
			}else{
				bytes.push(size);
				break;
			}
		}
		
		bytes = bytes.concat(chunk);
	}
	
	return bytes;
}

function NAEncodeBase64(input){
	return cryptico.b256to64(cryptico.bytes2string(input));
}

function NADecodeBase64(input){
	return cryptico.string2bytes(cryptico.b64to256(input));
}




/* ---- NAClient ---- 
   NexAuth client interface.
 */
function NAClient(){
	this.session = new NASession();
	this.curReq = null;
	this.queue = null;
	this.endpoint = null;
	this.userName = "TestUser";
	this.password = "TestHash";
}

NAClient.prototype={};

NAClient.prototype.setEndpoint=function(ep){
	if(ep == this.endpoint)
		return;
	this.endpoint = ep;
	this.abort();
}

NAClient.prototype.setLoginInfo=function(user, pass){
	if(user == this.userName &&
	   pass == this.password){
		return;
	}
	this.userName = user;
	this.password = pass;
	this.abort();
}

/*
 
 req = {
	cmd: 'CommandName',
	params: [[20,40,60], {a: 'yeah!'}],
	onDone: function(chunks){ ... },
	onError: function(phase, msg){ ... },
	onConnected: function(){ ... },
	onAuthorized: function(greeting){ ... },
	onAborted: function(){ ... },
	onStarted: function(){ ... }
 }
 
 */

NAClient.prototype.request=function(req){
	if(this.endpoint == null){
		throw "endpoint not set";
	}
	
	this.queue.push(req);
	
	// if there is already running request,
	// the new request will be performed when the old one completes
	// (even when error)
	if(!this.curReq)
		this.runCurrentRequest();
}

NAClient.prototype.abort=function(){
	//console.error('hey!')
	this.session.disconnect();
	if(this.curReq){
		var req = this.curReq;
		if(req.onAborted){
			req.onAborted();
		}
		if(req.onAbort){
			req.onAbort();
		}
		this.curReq = null;
	}
	for(var i in this.queue){
		var req = this.queue[i];
		if(req.onAborted){
			req.onAborted();
		}
		if(req.onAbort){
			req.onAbort();
		}
		this.curReq = null;
	}
	this.queue = [];
}

NAClient.prototype.runCurrentRequest=function(){
	if(!this.curReq){
		if(this.queue.length > 0){
			this.curReq = this.queue.shift();
			try{
				//console.debug("starting request "+NAStringFromBytes(this.curReq.chunks[0]));
			}catch(e){}
			if(this.curReq.onStarted)
				this.curReq.onStarted();
		}else{
			return;
		}
	}
	var self = this;
	var req = this.curReq;
	if(this.session.state == 'NotConnected'){
		// first we should connect
		try{
			this.session.connect(this.endpoint,
								 function(a,b){
								 self.onConnected(a,b,req);
								 });
		}catch(e){
			if(req.onError){
				req.onError('Connect', e);
			}
			this.curReq = null;
		}
	}else if(this.session.state == 'Connecting'){
		// wait till connection completion.
	}else if(this.session.state == 'NotAuthorized'){
		/// we should authorize
		try{
			this.session.authorize(this.identity(),
								   function(a,b){
								   self.onAuthorized(a,b,req);
								   });
		}catch(e){
			if(req.onError){
				req.onError('Authorization', e);
			}
			this.curReq = null;
		}
	}else if(this.session.state == 'Authorizing'){
		// wait till authorization completion.
	}else if(this.session.state == 'Connected'){
		try{
			this.session.command(req.cmd, req.params,
								 function(a,b){
								 self.onDone(a,b,req);
								 });
		}catch(e){
			if(req.onError){
				req.onError('Command', e);
			}
			this.curReq = null;
		}
	}else{
		throw "unrecognized state "+this.session.state+" detected!"
	}
}

NAClient.prototype.identity=function(){
	var passBase = this.passwordSalt + ':' + this.password;
	var passHash = sha256.hex(passBase);
	return this.userName + ':' + passHash;
}

NAClient.prototype.onConnected=function(succeeded, msg, req){
	if(req!=this.curReq)
		return this.runCurrentRequest();
	
	if(succeeded){
		if(req.onConnected){
			req.onConnected();
		}
		this.passwordSalt = msg;
		this.runCurrentRequest();
	}else{
		if(req.onError){
			req.onError('Connect', msg);
		}
		this.curReq = null;
		this.runCurrentRequest();
	}
    return null;
}

NAClient.prototype.onAuthorized=function(succeeded, msg, req){
	if(req!=this.curReq)
		return this.runCurrentRequest();
	
	if(succeeded){
		if(req.onAuthorized){
			req.onAuthorized(msg);
		}
		this.runCurrentRequest();
	}else{
		if(req.onError){
			if(msg=="session ID not found"){
				this.session.disconnect();
				this.runCurrentRequest();
				return null;
			}
			req.onError('Authorization', msg);
		}
		this.curReq = null;
		this.runCurrentRequest();
	}
    return null;
}

NAClient.prototype.onDone=function(succeeded, obj, req){
	if(req!=this.curReq)
		return this.runCurrentRequest();
	
	
	if(succeeded){
		if(req.onDone){
			try{
				req.onDone(obj);
			}catch(e){
				if(req.onError){
					req.onError('Command', e);
				}
			}
		}
		this.curReq = null;
		this.runCurrentRequest();
	}else{
		if(req.onError){
			var err = obj;
			// error on this phase can be caused by session expiration.
			// in this case, authorize again.
			if(err=="session ID not found"){
				this.session.disconnect();
				this.runCurrentRequest();
				return null;
			}
			req.onError('Command', obj);
		}
		this.curReq = null;
		this.runCurrentRequest();
	}
    return null;
}


