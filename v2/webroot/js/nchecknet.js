
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
        if (m.Function === "FillServerAlerts")   { FillServerAlerts(m);   return; }
        if (m.Function === "FillNmapAlerts")     { FillNmapAlerts(m);     return; }
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
        sendWithContext({ Function: "GetServerAlerts", AllSessions: $("#alerts-all-sessions").prop('checked') });
        sendWithContext({ Function: "GetNmapAlerts", AllSessions: $("#nmapalerts-all-sessions").prop('checked') });
        $("#charttype").val("select");
        $("#baseline-server").hide();
        $("#baseline-nmap").hide();
    });

    $("#alerts-all-sessions").on("change", function () {
        sendWithContext({ Function: "GetServerAlerts", AllSessions: $(this).prop('checked') });
    });

    $("#nmapalerts-all-sessions").on("change", function () {
        sendWithContext({ Function: "GetNmapAlerts", AllSessions: $(this).prop('checked') });
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
        sendWithContext({ Function: "GetServerAlerts", AllSessions: $("#alerts-all-sessions").prop('checked') });
        sendWithContext({ Function: "GetNmapAlerts", AllSessions: $("#nmapalerts-all-sessions").prop('checked') });
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

function formatAlertData(infoType, data) {
    if (!data) return '';
    switch (infoType) {
        case 'Listener':
            return (data.proto || '') + ' ' + (data.ip || '') + ':' + (data.port || '') +
                   (data.command ? ' (' + data.command + ')' : '');
        case 'Fwrule':
            return (data.proto || '') + ' port ' + (data.port || '') +
                   (data.ruletype ? ' ' + data.ruletype : '') +
                   (data.chain ? ' chain:' + data.chain : '') +
                   (data.ip_from ? ' from:' + data.ip_from : '') +
                   (data.ip_to ? ' to:' + data.ip_to : '');
        case 'Interface':
            return (data.name || '') +
                   (data.v4addresses && data.v4addresses.length ? ' v4:' + data.v4addresses.join(',') : '') +
                   (data.v6addresses && data.v6addresses.length ? ' v6:' + data.v6addresses.join(',') : '');
        case 'Route':
            return (data.dest || '') +
                   (data.gateway ? ' via ' + data.gateway : '') +
                   (data.interface ? ' dev ' + data.interface : '');
        default:
            return JSON.stringify(data);
    }
}

function FillServerAlerts(m) {
    const alerts = JSON.parse(m.AlertsJSON || '[]');
    if (alerts.length === 0) {
        $("#ServerAlertsTable").html('<p style="margin-top:10px;">No alerts found.</p>');
        return;
    }
    let html = '<table class="table table-sm table-striped table-bordered" style="margin-top:10px;">' +
               '<thead><tr><th>InfoType</th><th>What</th><th>Baseline</th><th>Reference Id</th><th>Data</th></tr></thead><tbody>';
    for (const a of alerts) {
        html += '<tr>' +
            '<td>' + escHtml(a.InfoType) + '</td>' +
            '<td>' + escHtml(a.What) + '</td>' +
            '<td>' + escHtml(a.Sid1) + '</td>' +
            '<td>' + escHtml(a.Sid2) + '</td>' +
            '<td>' + escHtml(formatAlertData(a.InfoType, a.Data)) + '</td>' +
            '</tr>';
    }
    html += '</tbody></table>';
    $("#ServerAlertsTable").html(html);
}

function FillNmapAlerts(m) {
    const alerts = JSON.parse(m.NmapAlertsJSON || '[]');
    if (alerts.length === 0) {
        $("#NmapAlertsTable").html('<p style="margin-top:10px;">No alerts found.</p>');
        return;
    }
    let html = '<table class="table table-sm table-striped table-bordered" style="margin-top:10px;">' +
               '<thead><tr><th>SessionID</th><th>Date</th><th>Proto</th><th>Port</th><th>Status</th></tr></thead><tbody>';
    for (const a of alerts) {
        const d = a.Data || {};
        html += '<tr>' +
            '<td>' + escHtml(a.SessionID) + '</td>' +
            '<td>' + escHtml(a.Date) + '</td>' +
            '<td>' + escHtml(d.proto || '') + '</td>' +
            '<td>' + escHtml(d.port || '') + '</td>' +
            '<td>' + escHtml(d.status || '') + '</td>' +
            '</tr>';
    }
    html += '</tbody></table>';
    $("#NmapAlertsTable").html(html);
}

function escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
