
$(document).ready(Ready);

var ws;


function Ready() {

    $('.nav-tabs > li:first-child > a')[0].click();


    mermaid.initialize({
        securityLevel: 'antiscript',
    });

    wsstring = "wss://";
    if (window.location.host == "127.0.0.1:8086") {
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
        if (m.Function == "Error") {
            alert(m.ArrData[0]);
            return;
        }
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
        if (m.Function == "FillChartReport") {
            FillChartReport(m);
            return;
        }
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed");
        window.location.assign("/index.html");
    };

    $("#logoff").on("click", function () {
        window.location.assign("/logoff");
    });

    $("#Servers").on("change", function () {
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



    $("#charthide").on("click", RedrawChart);

    $("#charttype").on("change", RedrawChart);

    $("#charttabitem").on('shown.bs.tab', function (e) {
        var target = $(e.target).attr("href");
        $("#chartreport").html("<pre class='mermaid' id=mermaidchartreport></pre>");
        $("#charthide").prop('checked', false);
        if (target == "#tab-2") {
            RedrawChart();
            return;
        }
    });
}

function RedrawChart() {
    unhide = $("#charthide").prop('checked');
    m = {};
    m.Function = "GetUfwListenChart";
    if (unhide) {
        m.Hide = "unhide";
    } else {
        m.Hide = "hide";
    }
    SendMessage(m);
}

function SendMessage(m) {
    unhide = $("#charthide").prop('checked');
    if (unhide) {
        m.Hide = "unhide";
    } else {
        m.Hide = "hide";
    }
    m.Hostname = $("#Servers").val();
    m.SessionID = $("#SessionIDs").val();
    m.ChartType = $("#charttype").val();

    ws.send(JSON.stringify(m));
}

function GetMessage() {
    m = {};
    m.Function = "GetServers";
    SendMessage(m);
}


function FillSessionIDs(m) {

    $('.nav-tabs > li:first-child > a')[0].click();

    $("#SessionIDs").find('option').remove();

    s0 = "";
    for (i = m.ArrData.length - 1; i > -1; --i) {
        s = m.ArrData[i];
        $("#SessionIDs").append('<option value="' + s + '">' + s + '</option>');
        if (i == m.ArrData.length - 1) {
            s0 = s;
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


    $('.nav-tabs > li:first-child > a')[0].click();

    s0 = "";
    for (i = 0; i < m.ArrData.length; ++i) {
        s = m.ArrData[i];
        if (i == 0) {
            s0 = s;
        }
        $("#Servers").append('<option value="' + s + '">' + s + '</option>');
    }

    if (s0.length > 0) {
        mo = {};
        mo.Function = "GetSessionIDs";
        mo.Hostname = s0;
        SendMessage(mo);
    }
}

function FillChartReport(m) {
    FillChart("#chartreport", m.ArrData[0]);
    setTimeout(function () {
        $(".hidefwrule").on("click", function () {
            csum = $(this).attr("id");
            mo = {};
            mo.Function = "HideFwrule";
            mo.Csum = csum;
            SendMessage(mo);
        });
        $(".hidelistener").on("click", function () {
            csum = $(this).attr("id");
            mo = {};
            mo.Function = "HideListener";
            mo.Csum = csum;
            console.log(csum);
            SendMessage(mo);
        });
        $(".Fwcomment").on("change", function () {
            csum = $(this).attr("id");
            cmt = $(this).val();
            mo = {};
            mo.Function = "ChangeFwComment";
            mo.Csum = csum;
            mo.Data = cmt;
            SendMessage(mo);
        });
        $(".Liscomment").on("change", function () {
            csum = $(this).attr("id");
            cmt = $(this).val();
            mo = {};
            mo.Function = "ChangeLisComment";
            mo.Csum = csum;
            mo.Data = cmt;
            SendMessage(mo);
        });
    }, 500);
}

function FillChart(d, c) {
    $("#mermaidchartreport").removeAttr("data-processed");
    $(d).html(c);
    mermaid.init();
}

function FillNmapSuggestion(m) {
    $("#nmapsuggestion").html("<pre class='mermaid' id=mermaidnmap></pre>");
    $("#mermaidnmap").removeAttr("data-processed");
    $("#mermaidnmap").html(m.ArrData[0]);
    $("#nmaprawcollector").html("");

    mermaid.init();

    setTimeout(function () {
        $(".IFN").on("click", function () {
            id = $(this).attr("id");
            m.Function = "GetNmapCollector";
            m.Data = id;
            SendMessage(m);
        });

    }, 500);

}

function FillData(m) {
    $("#DataTabCol1").html("<pre>" + m.ArrData[0] + "</pre>");
}
function FillNmapCollector(m) {
    $("#nmaprawcollector").html("<br/><pre>" + m.ArrData[0] + "</pre>");
}

