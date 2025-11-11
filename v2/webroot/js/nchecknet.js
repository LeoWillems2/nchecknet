
$(document).ready(Ready);

var ws;

function Ready() {
    ws = new WebSocket("ws://" + window.location.host + "/ws");

    ws.onopen = () => {
        console.log("WebSocket connection established");
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
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed");
        //setTimeout(Ready, 5000);
    };
}

function SendMessage(message) {
    ws.send(JSON.stringify(message));
}  

function GetMessage() {
    m = {};
    m.Function = "GetServers";
    SendMessage(m);
}


function FillSessionIDs(m) {
    $("#SessionIDs").find('option').remove();

    for (i = m.ArrData.length-1; i> -1;  --i) {
        s = m.ArrData[i];
        $("#SessionIDs").append('<option value="' + s + '">' + s + '</option');
    }
}

function FillServers(m) {
    s0 = "";
    for (i=0; i < m.ArrData.length; ++i){
        s = m.ArrData[i];
        if (i==0){
            s0=s;
        }
        $("#Servers").append('<option value="'+s+'">'+s+'</option');
    }

    if (s0.length > 0){
        m = {};
        m.Function = "GetSessionIDs";
        m.Hostname = s0;
        SendMessage(m);
    }
}
