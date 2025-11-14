
$(document).ready(Ready);

var ws;


function Ready() {


    $("#nmapsuggestion").html("<pre class='mermaid' id=mermaidnmap></pre><div id=x></div><div id=intbuttons></div>");
    $('.nav-tabs > li:first-child > a')[0].click();

    //const mermaidAPI = mermaid.mermaidAPI
    //mermaidAPI.initialize({
	//startOnLoad: false
    //});
	mermaid.initialize({
	  securityLevel: 'antiscript',
	});

    wsstring = "wss://";
    if (window.location.host == "127.0.0.1:8087" ) {
        wsstring = "ws://";
    }
    ws = new WebSocket(wsstring + window.location.host + "/ws");

    ws.onopen = () => {
        //console.log("WebSocket connection established");
        GetMessage();
    };

    ws.onmessage = (event) => {
        //console.log(event.data);
        m = JSON.parse(event.data);
        if (m.Function == "FillServers") {
            FillServers(m);
            return;
        }
        if (m.Function == "FillSessionIDs") {
            FillSessionIDs(m);
            return;
        }
        if (m.Function == "FillNmapSuggestion") {
            FillNmapSuggestion(m);
            return;
        }
        if (m.Function == "FillData") {
            FillData(m);
            return;
        }
        if (m.Function == "FillNmapCollector") {
            FillNmapCollector(m);
            return;
        }
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed");
    };


    $("#Servers").on("change", function() {
        hn = $(this).val();
        mo = {};
        mo.Function = "GetSessionIDs";
        mo.Hostname = hn;
        SendMessage(mo);
    });

    $("#SessionIDs").on("change", function () {
        si = $(this).val();
        mo = {};
        mo.Function = "GetNmapSuggestion";
        mo.Hostname = $("#Servers").val();
        mo.SessionID = si;
        SendMessage(mo);

        mo.Function = "GetData";
        SendMessage(mo);
    });

}

function SendMessage(message) {
	//console.log(JSON.stringify(message));
    ws.send(JSON.stringify(message));
}  

function GetMessage() {
    m = {};
    m.Function = "GetServers";
    SendMessage(m);
}


function FillSessionIDs(m) {
    $("#SessionIDs").find('option').remove();

    s0 = "";
    for (i = m.ArrData.length-1; i> -1;  --i) {
        s = m.ArrData[i];
        $("#SessionIDs").append('<option value="' + s + '">' + s + '</option>');
        if (i==m.ArrData.length-1){
            s0=s;
        }
    }

    if (s0.length > 0) {
        mo = {};
        mo.Function = "GetNmapSuggestion";
        mo.Hostname = m.Hostname;
        mo.SessionID = s0;
        SendMessage(mo);

        mo = {};
        mo.Function = "GetData";
        mo.Hostname = m.Hostname;
        mo.SessionID = s0;
        SendMessage(mo);
    }
}

function FillServers(m) {
    s0 = "";
    for (i=0; i < m.ArrData.length; ++i){
        s = m.ArrData[i];
        if (i==0){
            s0=s;
        }
        $("#Servers").append('<option value="'+s+'">'+s+'</option>');
    }

    if (s0.length > 0){
        mo = {};
        mo.Function = "GetSessionIDs";
        mo.Hostname = s0;
        SendMessage(mo);
    }
}

function FillNmapSuggestion(m) {   


   $("#mermaidnmap").html(m.ArrData[0]);
   //$("#intbuttons").html(m.ArrData[1]);
    $("#nmaprawcollector").html("");

   mermaid.init();

    setTimeout(function () {
        $("#mermaidnmap").removeAttr("data-processed");
	    $(".IFN").on("click", function() {
		id = $(this).attr("id");
		m.Function = "GetNmapCollector";
		m.Hostname = $("#Servers").val();
		m.SessionID = $("#SessionIDs").val();
		m.Data = id;
		SendMessage(m);
	    });
	    $("#XYZ").on("click", function() {
		console.log("XYZ");
	    });
    }, 1000);

}

function FillData(m) {
    $("#DataTabCol1").html("<pre>"+m.ArrData[0]+"</pre>");
}
function FillNmapCollector(m) {
    $("#nmaprawcollector").html("<br/><pre>"+m.ArrData[0]+"</pre>");
}
