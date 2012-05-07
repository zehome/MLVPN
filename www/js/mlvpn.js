var url = "http://localhost:1040/status";
var bwchart;
var bwchart_updateTimer;
var bwchart_maxpoints = 100;
var mlvpn_tunnels = [];

function bwchart_setup(container)
{
    bwchart = new Highcharts.Chart({
        chart: {
            renderTo: container,
            type: 'area',
            animation: false,
            height: 350,
        },
        title: {
            text: 'Bandwidth utilization'
        },
        xAxis: {
            type: 'datetime',
            tickPixelInterval: 150
        },
        yAxis: {
            title: {
                text: 'Bytes/s'
            },
        },
        plotOptions: {
            series: {
                stacking: 'normal',
                lineWidth: 1,
                lineColor: '#ffffff',
                marker: {
                    enabled: false
                }
            }
        },
        tooltip: false,
        legend: {
            align: 'left',
            verticalAlign: 'top',
            y: 0,
            x: 50,
            floating: true,
            borderWidth: 0
        },
        credits: {
            enabled: false
        }
    });

    bwchart_updateTimer = setInterval(function() {
        $.getJSON(url,
            bwchart_refresh,
            function(json) {
                alert("Error: "+x);
                stopTimer(bwchart_updateTimer);
            }
        );
    }, 1000);
}

function pretty_print_size(size, factor, display_unit)
{
    var unit = "B";
    var value = size;
    var tsize = size * factor;

    if (tsize > 1024 * 1024 * 1024) {
        unit = "GiB";
        value = size / 1024 / 1024 / 1024;
    } else if (tsize > 1024 * 1024) {
        unit = "MiB";
        value = size / 1024 / 1024;
    } else if (tsize > 1024) {
        unit = "KiB";
        value = size / 1024;
    }
    if (display_unit)
        return Math.round(value) + " " + unit;
    else
        return Math.round(value);
}

function bwchart_refresh(data)
{
    var i, j;
    var series = bwchart.series;
    var now = (new Date()).getTime();
    for (i = 0; i < data.tunnels.length; i++)
    {
        var tun = data.tunnels[i];
        for(j = 0; j < series.length; j++)
        {
            var s = series[j];
            if (s.name == tun.name)
            {
                var shift = s.data.length > bwchart_maxpoints;
                var y = tun["sentbytes"] - s.lastValue;
                if (! y)
                    y = 0;
                s.lastValue = tun["sentbytes"];
                s.addPoint([now,y], false, shift);
                /* Update progress bar */
                var percentage = Math.round(y / tun["bandwidth"] * 100);
                $('#'+tun["name"]+' .bar').attr("style", 'width: '+percentage+'%');
                $('#'+tun["name"]+' .bw_up').html("Upload: <strong>"+pretty_print_size(y, 1.2, true)+"/s</strong>");
                break;
            }
        }
    }
    bwchart.redraw();
}

function initial_dump(json)
{
    console.log(json);

    /* setup chart */
    bwchart_setup('bwchart');

    /* tuntap if display */
    var tuntap = $('#tuntap');
    var container = $('<div>');

    /* All tunnels */
    mlvpn_tunnels = json.tunnels;
    for (var i = 0; i < mlvpn_tunnels.length; i++)
    {
        var tun = mlvpn_tunnels[i];
        var tundiv = $('<div id="'+tun["name"]+'">');
        tundiv.addClass("tun well");

        /* Status button */
        var statusbutton = $('<div class="btn status"><h1>'+tun.name+'</h1></div>')
        if (tun["status"] == "connected")
            statusbutton.addClass("btn-success");
        else if (tun["status"] == "waiting peer")
            statusbutton.addClass("btn-warning");
        else
            statusbutton.addClass("btn-danger");
        tundiv.append(statusbutton);

        /* Some informations */
        var basicinfos = $('<dl class="dl-horizontal">');
        basicinfos.append($('<dt>Mode</dt><dd>'+tun["mode"]+'</dd>'));
        basicinfos.append($('<dt>Encapsulation</dt><dd>'+tun["encap"]+'</dd>'));
        basicinfos.append($('<dt>Direction</dt><dd>'+
            tun["bindaddr"]+':'+tun["bindport"]+
            " <strong>-&gt;</strong> "+
            tun["destaddr"]+':'+tun["destport"]+'</dd>'));
        tundiv.append(basicinfos);

        /* BW Usage if appropriate */
        if (tun["bandwidth"] != "0" || 1)
        {
            var progressbar = $('<div class="progress progress-sucess progress-striped active"></div>');
            progressbar.append($('<div class="bar" style="width: 0%;"></div>'));
            tundiv.append(progressbar);
            tundiv.append($('<span class="bw_up">Upload: 0 Bytes/s</span>'));
            tundiv.append($('<span class="bw_down">Download: 0 Bytes/s</span>'));
        }
        container.append(tundiv);

        /* Chart series */
        bwchart.addSeries({
            type: 'area',
            name: tun["name"],
            lastValue: 0,
            data: (function() {
                    var data = [];
                    var time = (new Date()).getTime();
                    var i;
                    for (i = -bwchart_maxpoints; i < 0; i++) {
                        data.push({
                            x: time + i * 1000,
                            y: null
                        });
                    }
                    return data;
                })()
        });
    }
    tuntap.html(container);
}

$().ready(function()
{
    $.getJSON(url,
        initial_dump,
        function(json) {
            alert("Error: "+x);
        }
    );
});

