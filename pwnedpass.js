

// module for checking passwords against a set of known exposed passwords
var PwnedPass = (function () {


    //haveibeenpwned.com/Passwords
    var apiURL = "https://api.pwnedpasswords.com/range/";
    var GitHubSrc = "jpxor-pwnedpass.js";


    // Calls to haveibeenpwned should be rate limited
    var RateLimit = 2000; // ms
    var throttle = throttler(RateLimit);


    // A User-Agent HTTP header is required by haveibeenpwned 
    var UserAgent = GitHubSrc;


    // httpGET used to call haveibeenpwned API
    function httpGET(url, callback) {
        var request = new XMLHttpRequest();
        request.onreadystatechange = function () {
            if (request.readyState == 4 && request.status == 200) {
                callback(request.responseText);
            }
        }
        request.open("GET", url, true);
        request.setRequestHeader("User-Agent", UserAgent);
        request.send(null);
    }


    // isValidSHA1 allows us to check whether a 
    // password input is plaintext or sha-1 hash.
    function isValidSHA1(str) {
        var regex = /[a-fA-F0-9]{40}/g;
        return str.search(regex) >= 0;
    }


    // doSHA1 is used because we need the SHA-1 hash of a password
    function doSHA1(plaintext) {
        if (typeof crypto.subtle.digest === "function") { 
            var buffer = new TextEncoder("utf-8").encode(plaintext);
            return crypto.subtle.digest("SHA-1", buffer).then(function (hashbuffer) {
                var hexCodes = [];
                var padding = '00000000';
                var view = new DataView(hashbuffer);
                for (var i = 0; i < view.byteLength; i += 4) {
                    var value = view.getUint32(i);
                    var stringValue = value.toString(16);
                    var paddedValue = (padding + stringValue).slice(-padding.length);
                    hexCodes.push(paddedValue);
                }
                return hexCodes.join("");
            });
        } else {
			return SHA1(plaintext);
        }
    }


	/**
	*  Secure Hash Algorithm (SHA1)
	*  http://www.webtoolkit.info/
	**/
	function SHA1 (msg) {
		function rotate_left(n,s) {
			var t4 = ( n<<s ) | (n>>>(32-s));
			return t4;
		};
		function lsb_hex(val) {
			var str="";
			var i;
			var vh;
			var vl;
			for( i=0; i<=6; i+=2 ) {
				vh = (val>>>(i*4+4))&0x0f;
				vl = (val>>>(i*4))&0x0f;
				str += vh.toString(16) + vl.toString(16);
			}
			return str;
		};
		function cvt_hex(val) {
			var str="";
			var i;
			var v;
			for( i=7; i>=0; i-- ) {
				v = (val>>>(i*4))&0x0f;
				str += v.toString(16);
			}
			return str;
		};
		function Utf8Encode(string) {
			string = string.replace(/\r\n/g,"\n");
			var utftext = "";
			for (var n = 0; n < string.length; n++) {
				var c = string.charCodeAt(n);
				if (c < 128) {
					utftext += String.fromCharCode(c);
				}
				else if((c > 127) && (c < 2048)) {
					utftext += String.fromCharCode((c >> 6) | 192);
					utftext += String.fromCharCode((c & 63) | 128);
				}
				else {
					utftext += String.fromCharCode((c >> 12) | 224);
					utftext += String.fromCharCode(((c >> 6) & 63) | 128);
					utftext += String.fromCharCode((c & 63) | 128);
				}
			}
			return utftext;
		};
		var blockstart;
		var i, j;
		var W = new Array(80);
		var H0 = 0x67452301;
		var H1 = 0xEFCDAB89;
		var H2 = 0x98BADCFE;
		var H3 = 0x10325476;
		var H4 = 0xC3D2E1F0;
		var A, B, C, D, E;
		var temp;
		msg = Utf8Encode(msg);
		var msg_len = msg.length;
		var word_array = new Array();
		for( i=0; i<msg_len-3; i+=4 ) {
			j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
			msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
			word_array.push( j );
		}
		switch( msg_len % 4 ) {
			case 0:
				i = 0x080000000;
			break;
			case 1:
				i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
			break;
			case 2:
				i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
			break;
			case 3:
				i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8    | 0x80;
			break;
		}
		word_array.push( i );
		while( (word_array.length % 16) != 14 ) word_array.push( 0 );
		word_array.push( msg_len>>>29 );
		word_array.push( (msg_len<<3)&0x0ffffffff );
		for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {
			for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
			for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
			A = H0;
			B = H1;
			C = H2;
			D = H3;
			E = H4;
			for( i= 0; i<=19; i++ ) {
				temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=20; i<=39; i++ ) {
				temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=40; i<=59; i++ ) {
				temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			for( i=60; i<=79; i++ ) {
				temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
				E = D;
				D = C;
				C = rotate_left(B,30);
				B = A;
				A = temp;
			}
			H0 = (H0 + A) & 0x0ffffffff;
			H1 = (H1 + B) & 0x0ffffffff;
			H2 = (H2 + C) & 0x0ffffffff;
			H3 = (H3 + D) & 0x0ffffffff;
			H4 = (H4 + E) & 0x0ffffffff;
		}
		var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
		return temp.toLowerCase();
	}
   

    // cleanInput parses the input types and provides a single params object 
    // in the format accepted by the doCheck function. A promise is used solely
    // for the ability to write: "cleanInput(,).then(doCheck)".
    function cleanInput(first, second) {
        return new Promise(async function (resolve, error) {
            var params = {}

            if (!first || 'string' !== typeof first) {
                error("must provide password or SHA-1 hash as first parameter");
                return;
            }
            if (!second) {
                error("must provide callbacks as the second parameter");
                return;
            }

            if ('function' === typeof second) {
                params.Pwned = second;
                params.Clean = function () { };
            } else {
                params = second;
                if (!params.Pwned) { params.Pwned = function (count) { console.log("This password is compromised, frequency: " + count); } }
                if (!params.Clean) { params.Clean = function () { }; }
            }

            if (!isValidSHA1(first) || params.ForceHash) {
                params.SHA1Hash = await Promise.resolve(doSHA1(first));
            } else {
                params.SHA1Hash = first;
            }
            resolve(params);
        });
    }


    // doCheck calls the haveibeenpwned API and compares password hashes,
    // A throttler is applied because calls to the haveibeenpwned API should 
    // be limited to one per 2 seconds.
    function doCheck(params) {
        throttle.apply(function () {
            var first5 = params.SHA1Hash.substr(0, 5);
            var remainder = params.SHA1Hash.substr(5).toUpperCase();

            httpGET(apiURL + first5, function (response) {
                var lines = response.split('\n');

                for (var i = 0; i < lines.length; ++i) {
                    respSplit = lines[i].split(':');
                    respHash = respSplit[0];
                    if (respHash === remainder) {
                        params.Pwned(parseInt(respSplit[1]));
                        return;
                    }
                }
                params.Clean();
            });
        });
    }


    // exposed module functions
    return {
        setUserAgent: function (userAgent) {
            UserAgent = userAgent + "-via-" + GitHubSrc;
        },
        setAPI: function(url) {
            apiURL = url;
        },
        setRateLimit: function(rate) {
            RateLimit = rate;
        },
        check: function (password, callbacks) {
            cleanInput(password, callbacks).then(doCheck).catch(console.error);
        }
    }
}());


//throttler module provided for rate limiting API calls
function throttler(period) {
    return (function () {

        var active = false
        var lastrun = 0;

        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        return {
            apply: async function (targetfunc) {
                if (active) {
                    return
                } active = true;

                var now = new Date().getTime();
                var remainder = lastrun + period - now;

                if (remainder > 0) {
                    await sleep(remainder);
                }
                targetfunc();
                lastrun = new Date().getTime();
                active = false;
            }
        }
    }());
}


