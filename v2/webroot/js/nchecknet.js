
$(document).ready(Ready);

// ws is the single WebSocket connection for the lifetime of the page.
let ws;

function Ready() {

    $('.nav-tabs > li:first-child > a')[0].click();

    $("#baseline-server").hide();
    $("#baseline-nmap").hide();
    $("#hide-hide").hide();

    mermaid.initialize({
        securityLevel: 'antiscript',
        maxTextSize: 2400000
    });

    const wsProto = window.location.host === "127.0.0.1:8086" ? "ws://" : "wss://";
    ws = new WebSocket(wsProto + window.location.host + "/ws");

    ws.onopen = () => {
        send({ Function: "GetServers" });
    };

    ws.onmessage = (event) => {
        const m = JSON.parse(event.data);
        console.log(m.Function);
        if (m.Function === "Error")              { alert(m.ArrData[0]); return; }
        if (m.Function === "FillServers")        { FillServers(m);        return; }
        if (m.Function === "FillSessionIDs")     { FillSessionIDs(m);     return; }
        if (m.Function === "FillNmapSuggestion") { FillNmapSuggestion(m); return; }
        if (m.Function === "FillData")           { FillData(m);           return; }
        if (m.Function === "FillNmapCollector")  { FillNmapCollector(m);  return; }
        if (m.Function === "FillChartReport")    { FillChartReport(m);    return; }
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed");
        window.location.assign("/index.html");
    };

    $("#logoff").on("click", function () {
        window.location.assign("/logoff");
    });

    $("#Servers").on("change", function () {
        const hn = $(this).val();
        sendWithContext({ Function: "GetSessionIDs", Hostname: hn });
        $("#charttype").val("select");
        $("#baseline-server").hide();
        $("#baseline-nmap").hide();
    });

    $("#SessionIDs").on("change", function () {
        sendWithContext({ Function: "GetNmapSuggestion" });
        sendWithContext({ Function: "GetData" });
        $("#charttype").val("select");
        $("#baseline-server").hide();
        $("#baseline-nmap").hide();
    });

    $("#baseline-server-val").on("click", doBaseLineServer);
    $("#baseline-nmap-val").on("click", doBaseLineNmap);

    $("#charthide").on("click", RedrawChart);
    $("#charttype").on("change", RedrawChart);

    $("#charttabitem").on('shown.bs.tab', function () {
        $("#chartreport").html("<pre class='mermaid' id=mermaidchartreport></pre>");
        $("#charthide").prop('checked', false);
    });

    $("#datatabitem").on('shown.bs.tab', function () {
        sendWithContext({ Function: "GetData" });
    });
}

// send transmits m over the WebSocket exactly as given.
function send(m) {
    ws.send(JSON.stringify(m));
}

// sendWithContext enriches m with the current UI state (hostname, session, chart type,
// hide flag) then transmits it. Values already set on m take precedence over context.
function sendWithContext(m) {
    const msg = {
        Hostname:  $("#Servers").val(),
        SessionID: $("#SessionIDs").val(),
        ChartType: $("#charttype").val(),
        Hide:      $("#charthide").prop('checked') ? "unhide" : "hide",
    };
    Object.assign(msg, m);
    send(msg);
}

function doBaseLineServer() {
    sendWithContext({
        Function:       "SetBaselineServer",
        BaselineServer: $("#baseline-server-val").prop('checked'),
    });
    setTimeout(RedrawChart, 500);
}

function doBaseLineNmap() {
    sendWithContext({
        Function:    "SetBaselineNmap",
        BaselineNmap: $("#baseline-nmap-val").prop('checked'),
    });
}

function RedrawChart() {
    sendWithContext({ Function: "GetFwListenChart" });
}

function FillSessionIDs(m) {

    $('.nav-tabs > li:first-child > a')[0].click();

    $("#SessionIDs").find('option').remove();

    let s0 = "";
    for (let i = m.ArrData.length - 1; i > -1; --i) {
        const s = m.ArrData[i];
        $("#SessionIDs").append('<option value="' + s + '">' + s + '</option>');
        if (i === m.ArrData.length - 1) {
            s0 = s;
        }
    }

    if (s0.length > 0) {
        sendWithContext({ Function: "GetNmapSuggestion" });
    }
}

function FillServers(m) {

    $('.nav-tabs > li:first-child > a')[0].click();

    $("#Servers").find('option').remove();

    let s0 = "";
    for (let i = 0; i < m.ArrData.length; ++i) {
        const s = m.ArrData[i];
        if (i === 0) { s0 = s; }
        $("#Servers").append('<option value="' + s + '">' + s + '</option>');
    }

    if (s0.length > 0) {
        sendWithContext({ Function: "GetSessionIDs", Hostname: s0 });
    }
}

function FillChartReport(m) {

    if ($("#charttype").val() === "select") {
        $("#hide-hide").hide();
        $("#baseline-server").hide();
        $("#baseline-nmap").hide();
        $("#chartreport").html("");
        return;
    }

    $("#baseline-server-val").prop('checked', m.BaselineServer);
    $("#baseline-nmap-val").prop('checked', m.BaselineNmap);
    $("#baseline-server-id").html(m.BaselineServerID);
    $("#baseline-nmap-id").html(m.BaselineNmapID);

    if ($("#charttype").val() === "nmapchart") {
        $("#hide-hide").hide();
        $("#baseline-server").hide();
        $("#baseline-nmap").show();
    } else {
        $("#hide-hide").show();
        $("#baseline-server").show();
        $("#baseline-nmap").hide();
    }

    FillChart("#chartreport", m.ArrData[0]);

    // Wire up interactive buttons after Mermaid has finished rendering.
    setTimeout(function () {
        $(".hidefwrule").on("click", function () {
            sendWithContext({ Function: "HideFwrule", Csum: $(this).attr("id") });
        });
        $(".hidelistener").on("click", function () {
            sendWithContext({ Function: "HideListener", Csum: $(this).attr("id") });
        });
        $(".Fwcomment").on("change", function () {
            sendWithContext({ Function: "ChangeFwComment", Csum: $(this).attr("id"), Data: $(this).val() });
        });
        $(".Liscomment").on("change", function () {
            sendWithContext({ Function: "ChangeLisComment", Csum: $(this).attr("id"), Data: $(this).val() });
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

    // Wire up interface buttons after Mermaid has finished rendering.
    setTimeout(function () {
        $(".IFN").on("click", function () {
            // $(this).attr("id") is "IFN-<index>"; the server strips the "IFN-" prefix itself.
            sendWithContext({ Function: "GetNmapCollector", Data: $(this).attr("id") });
        });
    }, 500);
}

function FillData(m) {
    $("#DataTabCol1").html("<pre>" + m.ArrData[0] + "</pre>");
}

function FillNmapCollector(m) {
    $("#nmaprawcollector").html("<br/><pre>" + m.ArrData[0] + "</pre>");
}
