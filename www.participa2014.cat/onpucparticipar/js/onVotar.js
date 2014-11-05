function formvalidation(idioma){
	var error=0;
	var msg="";

	if(document.forms.frm.municipi.value==''){
		error==1;			
		if(idioma==1){
			msg+="<li>El <b>municipio</b> es obligatorio.</li>";
		}else{
			msg+="<li>El <b>municipi</b> és obligatori.</li>";
		}		
	}else if(document.forms.frm.municipi.value!=document.forms.frm.desc_municipi.value){
		error==1;			
		if(idioma==1){
			msg+="<li>Tiene que seleccionar el <b>municipio</b> del listado emergente.</li>";
		}else{
			msg+="<li>S'ha de seleccionar el <b>municipi</b> del llistat emergent.</li>";
		}
	}
	
	if (!esMunLocal){
		if(document.forms.frm.via.value==''){
			error==1;			
			if(idioma==1){
				msg+="<li>La <b>vía</b> es obligatoria.</li>";
			}else{
				msg+="<li>La <b>via</b> és obligatòria.</li>";
			}		
		}else if(document.forms.frm.via.value!=document.forms.frm.desc_via.value){
			error==1;			
			if(idioma==1){
				msg+="<li>Tiene que seleccionar la <b>vía</b> del listado emergente.</li>";
			}else{
				msg+="<li>S'ha de seleccionar la <b>via</b> del llistat emergent.</li>";
			}
		}
		
		if(document.forms.frm.tram.value==''){
			error==1;			
			if(idioma==1){
				msg+="<li>El <b>tramo de la vía</b> es obligatorio.</li>";
			}else{
				msg+="<li>El <b>tram de la via</b> és obligatori.</li>";
			}		
		}else if(document.forms.frm.tram.value!=document.forms.frm.desc_tram.value){
			error==1;			
			if(idioma==1){
				msg+="<li>Tiene que seleccionar el <b>tramo de la vía</b> del listado emergente.</li>";
			}else{
				msg+="<li>S'ha de seleccionar el <b>tram de la via</b> del llistat emergent.</li>";
			}
		}
	}
	
	if(document.forms.frm.cognom.value==''){
		error==1;			
		if(idioma==1){
			msg+="<li>El <b>primer apellido</b> es obligatorio.</li>";
		}else{
			msg+="<li>El <b>primer cognom</b> és obligatori.</li>";
		}		
	}
	
	if(error==1){
		if(idioma==1){
			msg="Revise esta información y vuelva a intentarlo:<br/><br/><ul>"+msg+"</ul>";
		}else{
			msg="Reviseu aquesta informació i intenteu-ho de nou:<br/><br/><ul>"+msg+"</ul>";
		}
		omplirMsg(msg);
		showPopup();
	}else{
		var hash="";
		if(esMunLocal){
			//hash=sha1Hash("k8BwrF-pZ9?r}v8"+document.forms.frm.codi_municipi.value);
			hash = "k8BwrF-pZ9?r}v8"+document.forms.frm.codi_municipi.value;
		}else{
			//hash=sha1Hash("k8BwrF-pZ9?r}v8"+document.forms.frm.codi_tram.value);			
			hash = "k8BwrF-pZ9?r}v8"+document.forms.frm.tram.value;
		}		
		var mypbkdf2 = new PBKDF2(hash, document.forms.frm.codi_municipi.value, 2000, 64);
		omplirMsg("0%");
		document.getElementById("tableTanca").style.display = 'none';
		showPopup();
		if(idioma==1){
			var status_callback = function(percent_done) {
				omplirMsg( "Espere un momento para visualizar su tarjeta de participación.");};
		}else{
			var status_callback = function(percent_done) {
				omplirMsg("Espereu un moment per visualitzar la vostra targeta de participació.");};
		}		
		var result_callback = function(key) {
				hidePopup();
				document.getElementById("tableTanca").style.display = 'table';
				urlValidation(key,idioma);
			};
		mypbkdf2.deriveKey(status_callback,result_callback);
	}
}

function sha1Hash(msg)
{
    // constants [4.2.1]
    var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
 
    // PREPROCESSING
  
    msg += String.fromCharCode(0x80); // add trailing '1' bit to string [5.1.1]
 
    // convert string msg into 512-bit/16-integer blocks arrays of ints [5.2.1]
    var l = Math.ceil(msg.length/4) + 2;  // long enough to contain msg plus 2-word length
    var N = Math.ceil(l/16);              // in N 16-int blocks
    var M = new Array(N);
    for (var i=0; i<N; i++) {
        M[i] = new Array(16);
        for (var j=0; j<16; j++) {  // encode 4 chars per integer, big-endian encoding
            M[i][j] = (msg.charCodeAt(i*64+j*4)<<24) | (msg.charCodeAt(i*64+j*4+1)<<16) |
                      (msg.charCodeAt(i*64+j*4+2)<<8) | (msg.charCodeAt(i*64+j*4+3));
        }
    }
    // add length (in bits) into final pair of 32-bit integers (big-endian) [5.1.1]
    M[N-1][14] = ((msg.length-1) >>> 30) * 8;
    M[N-1][15] = ((msg.length-1)*8) & 0xffffffff;
 
    // set initial hash value [5.3.1]
    var H0 = 0x67452301;
    var H1 = 0xefcdab89;
    var H2 = 0x98badcfe;
    var H3 = 0x10325476;
    var H4 = 0xc3d2e1f0;
 
    // HASH COMPUTATION [6.1.2]
 
    var W = new Array(80); var a, b, c, d, e;
    for (var i=0; i<N; i++) {
 
        // 1 - prepare message schedule 'W'
        for (var t=0;  t<16; t++) W[t] = M[i][t];
        for (var t=16; t<80; t++) W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
 
        // 2 - initialise five working variables a, b, c, d, e with previous hash value
        a = H0; b = H1; c = H2; d = H3; e = H4;
 
        // 3 - main loop
        for (var t=0; t<80; t++) {
            var s = Math.floor(t/20); // seq for blocks of 'f' functions and 'K' constants
            var T = (ROTL(a,5) + f(s,b,c,d) + e + K[s] + W[t]) & 0xffffffff;
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = T;
        }
 
        // 4 - compute the new intermediate hash value
        H0 = (H0+a) & 0xffffffff;  // note 'addition modulo 2^32'
        H1 = (H1+b) & 0xffffffff;
        H2 = (H2+c) & 0xffffffff;
        H3 = (H3+d) & 0xffffffff;
        H4 = (H4+e) & 0xffffffff;
    }
 
    return H0.toHexStr() + H1.toHexStr() + H2.toHexStr() + H3.toHexStr() + H4.toHexStr();
}
 
//
// function 'f' [4.1.1]
//
function f(s, x, y, z)
{
    switch (s) {
    case 0: return (x & y) ^ (~x & z);
    case 1: return x ^ y ^ z;
    case 2: return (x & y) ^ (x & z) ^ (y & z);
    case 3: return x ^ y ^ z;
    }
}
 
//
// rotate left (circular left shift) value x by n positions [3.2.5]
//
function ROTL(x, n)
{
    return (x<<n) | (x>>>(32-n));
}
 
//
// extend Number class with a tailored hex-string method
//   (note toString(16) is implementation-dependant, and
//   in IE returns signed numbers when used on full words)
//
Number.prototype.toHexStr = function()
{
    var s="", v;
    for (var i=7; i>=0; i--) { v = (this>>>(i*4)) & 0xf; s += v.toString(16); }
    return s;
};

function addOpt(oCntrl, iPos, sTxt, sVal){
    var selOpcion = new Option(sTxt, sVal);
    oCntrl.options.add(selOpcion, iPos);
}


function omplirCombo(combo,dat,value,idioma){
	combo.options.length=0;
	if(idioma==1){
		addOpt(combo,0,"- Seleccionar -",0);
		if(value!='0'){
			$.ajax({url: dat + value + ".dat",
				datatype : "text",
				beforeSend: function() {},
				success: function(data, textStatus) {
					var lines=data.split(/\r\n|\r|\n/);
					var codiDesc;
					for (i = 0; i < lines.length; i++) {
						codiDesc=lines[i].split('=',3);
						 addOpt(combo,i+1,codiDesc[2],codiDesc[0]);
					}
				}
			});
		}
	}else{
		addOpt(combo,0,"- Seleccioneu -",0);
		if(value!='0'){
			$.ajax({url: dat + value + ".dat",
				datatype : "text",
				beforeSend: function() {},
				success: function(data, textStatus) {
					var lines=data.split(/\r\n|\r|\n/);
					var codiDesc;
					for (i = 0; i < lines.length; i++) {
						codiDesc=lines[i].split('=',3);
						 addOpt(combo,i+1,codiDesc[1],codiDesc[0]);
					}
				}
			});
		}
	}
	
	
 }

var esMunLocal=false;

function esMunicipiUnLocal(codiMun,idioma){
	$.ajax({url: (idioma==1?'.':'')+datMunUnLoc,
		datatype : "text",
		beforeSend: function() {},
		success: function(data, textStatus) {
			var lines=data.split(/\r\n|\r|\n/);			
			for (i = 0; i < lines.length; i++) {
				//alert(codiMun+"="+lines[i]);
				if(codiMun==lines[i]){
					document.forms.frm.via.value='';
					document.forms.frm.desc_via.value='';
					document.forms.frm.codi_via.value='';
					$('#via-holder .typeahead').typeahead('val', '');
					document.forms.frm.codi_municipi_via.value='';
					document.forms.frm.via.disabled='disabled';
					document.getElementById("divVia").style.display='none';
					document.getElementById("via-holder").style.display='none';
					document.getElementById("divTram1").style.display='none';
					document.getElementById("divTram2").style.display='none';
					document.forms.frm.via.style.backgroundColor='#eeeeee';
					document.forms.frm.tram.disabled='disabled';
					document.getElementById('viaOk').style.display = 'none';
					document.getElementById('viaKo').style.display = 'none';
					document.getElementById('tramOk').style.display = 'none';
					document.getElementById('tramKo').style.display = 'none';					
					document.forms.frm.cognom.disabled='';
					document.forms.frm.cognom.focus();
					if(document.forms.frm.cognom.value!=''){
						toggle_visibilityCognom('cognom', document.forms.frm.cognom.value);
					}
					esMunLocal=true;
					return;
				}
			}
			document.forms.frm.via.disabled='';	
			document.forms.frm.via.style.backgroundColor='#ffffff';
			document.getElementById("divVia").style.display='inline';
			document.getElementById("via-holder").style.display='inline';
			document.getElementById("divTram1").style.display='inline';
			document.getElementById("divTram2").style.display='table';
			if(document.forms.frm.codi_municipi_via.value!=document.forms.frm.codi_municipi.value){
				filtreVies(idioma);
				document.forms.frm.via.value='';
				document.forms.frm.desc_via.value='';
				document.forms.frm.codi_via.value='';
				document.forms.frm.codi_municipi_via.value=document.forms.frm.codi_municipi.value;
				$('#via-holder .typeahead').typeahead('val', '');				
				document.forms.frm.tram.disabled='disabled';
				document.forms.frm.cognom.disabled='disabled';
				document.forms.frm.butAccepta.disabled='disabled';
			}else{
				if(document.forms.frm.via.value!=''){
					toggle_visibilityVia('via', document.forms.frm.via.value,document.forms.frm.desc_via.value,idioma);
				}
			}
			document.forms.frm.via.focus();
			esMunLocal=false;
			return;
		}
	});
	
}

function toggle_visibilityCombo(name,value,valueHidden) {
	var e = document.getElementById(name+'Ok');
	var e2 = document.getElementById(name+'Ko');
    if(value!='' && value==valueHidden){
    	e.style.display = 'inline';
    	e2.style.display = 'none';
    	return true;
    }else{
    	e.style.display = 'none';
    	e2.style.display = 'inline';
    	return false;
    }
}

function toggle_visibilityMunicipi(name,value,valueHidden,idioma) {
	if(toggle_visibilityCombo(name,value,valueHidden)){
		document.forms.frm.tram.selectedIndex=0;
		document.getElementById('tramOk').style.display = 'none';
		document.getElementById('tramKo').style.display = 'none';
		esMunicipiUnLocal(document.forms.frm.codi_municipi.value,idioma);		
	}else{
		document.forms.frm.via.disabled='disabled';
		document.forms.frm.via.style.backgroundColor='#eeeeee';		
		document.forms.frm.tram.disabled='disabled';
		document.forms.frm.cognom.disabled='disabled';
		document.forms.frm.butAccepta.disabled='disabled';
	}
}

function toggle_visibilityVia(name,value,valueHidden,idioma) {
	if(toggle_visibilityCombo(name,value,valueHidden)){
		document.forms.frm.tram.disabled='';						
		if(document.forms.frm.codi_via_tram.value!=document.forms.frm.codi_via.value){
			filtreTrams(idioma);
			document.forms.frm.tram.value='';
			document.forms.frm.desc_tram.value='';
			document.forms.frm.codi_tram.value='';
			document.forms.frm.codi_via_tram.value=document.forms.frm.codi_via.value;
			//$('#tram-holder .typeahead').typeahead('val', '');
		}
		document.forms.frm.tram.focus();
	}else{
		document.forms.frm.tram.disabled='disabled';
		document.forms.frm.cognom.disabled='disabled';
		document.forms.frm.butAccepta.disabled='disabled';
	}
}

function toggle_visibilityTram(name,value,valueHidden) {
	/*if(toggle_visibilityCombo(name,value,valueHidden)){
		document.forms.frm.cognom.disabled='';		
		document.forms.frm.cognom.focus();
	}else{
		document.forms.frm.butAccepta.disabled='disabled';
		document.forms.frm.cognom.disabled='disabled';
	}*/
	var e = document.getElementById(name+'Ok');
	var e2 = document.getElementById(name+'Ko');
	if(value==0){
		document.forms.frm.butAccepta.disabled='disabled';
		document.forms.frm.cognom.disabled='disabled';
		e.style.display = 'none';
    	e2.style.display = 'inline';
	}else{
		document.forms.frm.cognom.disabled='';		
		document.forms.frm.cognom.focus();
		e.style.display = 'inline';
    	e2.style.display = 'none';
    	if(document.forms.frm.cognom.value!=''){
    		toggle_visibilityCognom('cognom', document.forms.frm.cognom.value);
    	}
	}
		
}

function toggle_visibilityCognom(name,value) {
	var e = document.getElementById(name+'Ok');
	var e2 = document.getElementById(name+'Ko');
    if(value==''){
    	e.style.display = 'none';
    	e2.style.display = 'none';
    	document.forms.frm.butAccepta.disabled='disabled';
    	
    }else if(!validaCognom(value)){
    	e.style.display = 'none';
    	e2.style.display = 'inline';
    	document.forms.frm.butAccepta.disabled='disabled';
    }else{
    	e.style.display = 'inline';
    	e2.style.display = 'none';
    	document.forms.frm.butAccepta.disabled='';		
		//document.forms.frm.butAccepta.focus();
    }
}

function cognomDintreRang(rang_inici,rang_fi,cognom){
	//alert(rang_inici+"|"+rang_fi+"|"+cognom+"|"+(cognom.localeCompare(rang_inici) >= 0 && cognom.localeCompare(rang_fi) <=0));
	return cognom.localeCompare(rang_inici) >= 0 && cognom.localeCompare(rang_fi) <0;
}

function treureAccents(strAccents) {
	var strAccents = strAccents.toUpperCase().split('');
	var strAccentsOut = new Array();
	var strAccentsLen = strAccents.length;
	var accents = 'ÀÁÂÃÄÅÒÓÔÕÕÖØÈÉÊËÇÐÌÍÎÏÙÚÛÜÑŠŸŽ';
	var accentsOut = "AAAAAAOOOOOOOEEEECDIIIIUUUUNSYZ";
	for (var y = 0; y < strAccentsLen; y++) {
	if (accents.indexOf(strAccents[y]) != -1) {
	strAccentsOut[y] = accentsOut.substr(accents.indexOf(strAccents[y]), 1);
	} else
	strAccentsOut[y] = strAccents[y];
	}
	strAccentsOut = strAccentsOut.join('');
	return strAccentsOut;
}

function urlValidation(hash,idioma){	
	var urlSerncera = (idioma==1?'.':'')+"./data/" + hash.charAt(0) + "/" + hash + ".h";
	//alert(urlSerncera);
	$.ajax({url: urlSerncera,
		datatype : "text",
		beforeSend: function() {},
		success: function(data, textStatus) {
			var camps;
			var lines=data.split(/\r\n|\r|\n/);
			var cognom=treureAccents(document.forms.frm.cognom.value);
			for (i = 0; i < lines.length; i++) {
				camps=lines[i].split('|');
				if(cognomDintreRang(camps[4],camps[5],cognom)){
					document.getElementById("municipi_punt").innerHTML = camps[0];
					document.getElementById("local").innerHTML = camps[1];
					
					if ( camps[2]==''){
						document.getElementById("divAdreca").style.display='none';
					}else{
						document.getElementById("divAdreca").style.display='table';
						document.getElementById("adreca").innerHTML = camps[2];							
					}
					document.getElementById("mesa").innerHTML = camps[3];
					
					document.getElementById("taula_cognom").innerHTML=obteCognomValidat(document.forms.frm.cognom.value);
					document.getElementById("taula_municipi").innerHTML=document.forms.frm.municipi.value;					
					if(esMunLocal){
						document.getElementById("domicili").style.display='none';
					}else{
						document.getElementById("domicili").style.display='inline';
						document.getElementById("taula_via").innerHTML=document.forms.frm.via.value;
					}
					
					
					showPopupTaula();					
					return;
				}
				
			}
			if(idioma==1){
        		omplirMsg("Los datos que ha introducido no permiten designar ningún local de participación. Por favor, verifique que son correctos y vuelva a intentarlo. Si el error persiste, puede contactar con el 012.");
            }else{
            	omplirMsg("Les dades que heu introduït no permeten designar cap local de participació. Si us plau, verifiqueu que són correctes i torneu a provar-ho. Si l'error persisteix, podeu trucar al 012.");
            }
        	showPopup();
			
		},
		error: function(jqXHR, textStatus, errorThrown) {
			if(idioma==1){
				omplirMsg("Se ha producido un error, por favor pongase en contacto llamando por teléfono con el 012 y comunicar el código de error 999.");
			}else{
				omplirMsg("S'ha produït un error, si us plau posis en contacte trucant per telèfon amb el 012 i comuniqueu el codi d'error 999.");
			}
			showPopup();
		},
		statusCode: {
            404: function() {
            	if(idioma==1){
            		omplirMsg("Los datos que ha introducido no permiten designar ningún local de participación. Por favor, verifique que son correctos y vuelva a intentarlo. Si el error persiste, puede contactar con el 012.");
	            }else{
	            	omplirMsg("Les dades que heu introduït no permeten designar cap local de participació. Si us plau, verifiqueu que són correctes i torneu a provar-ho. Si l'error persisteix, podeu trucar al 012.");
	            }
            	showPopup();
            }
         }
		});
	}

	function omplirMsg(text) {
		document.getElementById("msg").innerHTML = text;
	}

	function showPopup() {
		deshabilita();
	    $("#mask").fadeTo(500, 0.25);
	    $("#popup").show(); 
	    if(document.getElementById('tableTanca').style.display=='table'){
	    	document.forms.frm.butTanca.focus();
	    }
	}
	
	function hidePopup() {
		$('#popup').hide();
		$('#mask').hide();
		habilita();
		document.forms.frm.municipi.focus();
	}
	
	function showPopupTaula() {
		deshabilita();
	    $("#mask").fadeTo(500, 0.25);
	    $("#popupTaula").show();
	    if(document.forms.frm.butTancaTaula.style.display!='none'){
	    	document.forms.frm.butTancaTaula.focus();
	    }	    
	}
	
	function hidePopupTaula() {
		$('#popupTaula').hide();
		$('#mask').hide();
		habilita();
		document.forms.frm.municipi.focus();
	}
	
	function deshabilita(){
		//disabled_mun=document.forms.frm.municipi.disabled;
		document.forms.frm.municipi.disabled='disabled';
		document.forms.frm.via.disabled='disabled';		
		document.forms.frm.tram.disabled='disabled';
		document.forms.frm.cognom.disabled='disabled';
		document.forms.frm.butAccepta.disabled='disabled';
	}
	
	function habilita(){
		document.forms.frm.municipi.disabled='';
		if(document.forms.frm.via.value!=''){
			document.forms.frm.via.disabled='';
		}
		if(document.forms.frm.tram.value!='0'){
			document.forms.frm.tram.disabled='';
		}
		if(document.forms.frm.cognom.value!=''){
			document.forms.frm.cognom.disabled='';
		}
		
		document.forms.frm.butAccepta.disabled='';
	}

	function isInteger(s){
		var i;
	    for (i = 0; i < s.length; i++){   
	        // Check that current character is number.
	        var c = s.charAt(i);
	        if (((c < "0") || (c > "9"))) return false;
	    }
	    // All characters are numbers.
	    return true;
	}

	function stripCharsInBag(s, bag){
		var i;
	    var returnString = "";
	    // Search through string's characters one by one.
	    // If character is not in bag, append to returnString.
	    for (i = 0; i < s.length; i++){   
	        var c = s.charAt(i);
	        if (bag.indexOf(c) == -1) returnString += c;
	    }
	    return returnString;
	}
	


	
var datMun="./data/municipis.dat";
var datMunUnLoc="./data/municipisUnLocal.dat";
var datTram="./data/trams/";
var datVia="./data/vies/";

var charMap = {
	    "á": "a","à": "a","â": "a","ä": "a",
	    "é": "e","è": "e","ê": "e","ë": "e",
	    "í": "i","ì": "i","î": "i","ï": "i",
	    "ó": "o","ò": "o","ô": "o","ö": "o",
	    "ú": "u","ù": "u","û": "u","ü": "u",
	    "ñ": "n","ç": "c"
	};
var normalize = function (input) {
    $.each(charMap, function (unnormalizedChar, normalizedChar) {
        var regex = new RegExp(unnormalizedChar, 'gi');
        input = input.replace(regex, normalizedChar);
    });
    return input;
};
var queryTokenizer = function (q) {
    var normalized = normalize(q);
    return Bloodhound.tokenizers.whitespace(normalized);
};

function filtreMunicipis(idioma){
		
	var municipis = new Bloodhound({
	  datumTokenizer: Bloodhound.tokenizers.obj.nonword('nom_municipi_cerca'),
	  queryTokenizer: queryTokenizer,
	  limit:100,
	  prefetch: {ttl: 1,url:(idioma==1?'.':'')+datMun}     
	});
	 
	municipis.initialize();
	document.getElementById('carregant_mun').style.display='none';
	if(idioma==1){
		document.getElementById('municipi').placeholder='Municipio que consta en su DNI o su TIE';
	}else{
		document.getElementById('municipi').placeholder='Municipi que consta en el vostre DNI o la vostra TIE';
	}
	document.getElementById('municipi').disabled='';
	$('#municipi-holder .typeahead').typeahead(null,
		{
		  name: 'municipis',
		  displayKey: 'nom_municipi',		  
		  source: municipis.ttAdapter()
		}
	).on('typeahead:selected', function (obj, datum) {
		document.forms.frm.codi_municipi.value=datum.codi_municipi;		
		document.forms.frm.desc_municipi.value=datum.nom_municipi;
		document.forms.frm.municipi.value=datum.nom_municipi;		
		document.forms.frm.municipi.onchange();
		
	});	
}

function filtreVies(idioma){
	$('#via-holder .typeahead').typeahead('destroy');

	var nomViaCercaIdioma="nom_via_cerca_ca";
	if(idioma==1){
		nomViaCercaIdioma="nom_via_cerca_es";
	}
	
	var vies = new Bloodhound({
		  datumTokenizer: Bloodhound.tokenizers.obj.nonword(nomViaCercaIdioma),
		  queryTokenizer: queryTokenizer,
		  limit:100,
		  prefetch: {ttl: 1,url:(idioma==1?'.':'')+datVia+document.forms.frm.codi_municipi.value+'.dat'}
	});
	vies.clearPrefetchCache();
	vies.initialize(true);
	
	if(idioma==1){
		$('#via-holder .typeahead').typeahead(null,
			{
			  name: 'vies',
			  displayKey: 'nom_via_es',		  
			  source: vies.ttAdapter()
			}
		).on('typeahead:selected', function (obj, datum) {
			document.forms.frm.codi_via.value=datum.codi_via;		
			document.forms.frm.desc_via.value=datum.nom_via_es;
			document.forms.frm.via.value=datum.nom_via_es;
			document.forms.frm.via.onchange();
			
		});
	}else{
		$('#via-holder .typeahead').typeahead(null,
			{
			  name: 'vies',
			  displayKey: 'nom_via_ca',		  
			  source: vies.ttAdapter()
			}
		).on('typeahead:selected', function (obj, datum) {
			document.forms.frm.codi_via.value=datum.codi_via;		
			document.forms.frm.desc_via.value=datum.nom_via_ca;
			document.forms.frm.via.value=datum.nom_via_ca;
			document.forms.frm.via.onchange();
			
		});		
	}
}

function filtreTrams(idioma){
	omplirCombo(document.forms.frm.tram,(idioma==1?'.':'')+datTram,document.forms.frm.codi_via.value,idioma);
	/*$('#tram-holder .typeahead').typeahead('destroy');

	var trams = new Bloodhound({
		  datumTokenizer: Bloodhound.tokenizers.obj.whitespace('nom_tram'),
		  queryTokenizer: Bloodhound.tokenizers.whitespace,
		  limit:10,
		  prefetch: {ttl: 1,url:datTram+document.forms.frm.codi_via.value+'.dat'}
	});
	trams.clearPrefetchCache();
	trams.initialize(true);
	
	$('#tram-holder .typeahead').typeahead(null,
		{
		  name: 'trams',
		  displayKey: 'nom_tram',		  
		  source: trams.ttAdapter()
		}
	).on('typeahead:selected', function (obj, datum) {
		document.forms.frm.codi_tram.value=datum.codi_tram;		
		document.forms.frm.desc_tram.value=datum.nom_tram;
		document.forms.frm.tram.value=datum.nom_tram;
		document.forms.frm.tram.onchange();
		
	});*/
}

var versioApp="v1.5";

function iniciaPagina(){
	tagsVersions=document.getElementsByName("versioApp");
	for (var i=0; i<tagsVersions.length; i++){
		tagsVersions[i].innerHTML=versioApp;
	}
}

function validaCognom(cognom){
	var charcode;
	for(var i=0;i<cognom.length;i++){
		charcode=cognom.charCodeAt(i);
		if(!(charcode>64 && charcode<91 || charcode>96 && charcode<123 || charcode>191 && charcode<256 || charcode==39 || charcode==45 || charcode==32)){
			//alert(i+':'+charcode+':'+cognom.charAt(i));
			return false;
		}
	}
	return true;
}

function obteCognomValidat(cognom){
	var cognomValidat='';
	var charcode;
	for(var i=0;i<cognom.length;i++){
		charcode=cognom.charCodeAt(i);
		if(charcode>64 && charcode<91 || charcode>96 && charcode<123 || charcode>191 && charcode<256 || charcode==39 || charcode==45 || charcode==32){
			cognomValidat += cognom.charAt(i);
		}
	}
	return cognomValidat;
}