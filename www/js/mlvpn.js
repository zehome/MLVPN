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
            defaultSeriesType: 'spline',
            animation: {
                duration: 900,
                easing: 'easeInOutCubic'
            },
            shadow: true
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

            plotLines: [{
                value: 0,
                width: 1,
                color: '#808080'
            }]
        },
        tooltip: {
            formatter: function() {
                return '<b>'+ this.series.name +'</b><br/>'+
                Highcharts.dateFormat('%Y-%m-%d %H:%M:%S', this.x) +'<br/>'+
                Highcharts.numberFormat(this.y, 2);
            }
        },
        legend: {
            align: 'left',
            verticalAlign: 'top',
            y: 20,
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

function bwchart_refresh(data)
{
    var i, j;
    var series = bwchart.series;
    for (i = 0; i < data.tunnels.length; i++)
    {
        var tun = data.tunnels[i];
        for(j = 0; j < series.length; j++)
        {
            var s = series[j];
            if (s.name == tun.name)
            {
                var x = (new Date()).getTime();
                var y = tun["recvbytes"] - s.lastValue;
                if (! y)
                    y = 0;
                s.lastValue = tun["recvbytes"];
                console.log("x: "+x+" y: "+y);
                var shift = s.data.length > bwchart_maxpoints;
                s.addPoint([x,y], true, s.data.length > bwchart_maxpoints);
                break;
            }
        }
    }
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
        var tundiv = $('<div>');
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
            var progressbar = $('<div class="progress progress-sucess progress-striped active"><div class="bar" style="width: 42%;"></div></div>')
            tundiv.append(progressbar);
        }
        container.append(tundiv);

        /* Chart series */
        bwchart.addSeries({
            type: 'spline',
            name: tun["name"],
            lastValue: 0,
            data: (function() {
                    var data = [];
                    var time = (new Date()).getTime();
                    var i;
                    for (i = -bwchart_maxpoints; i < 0; i++) {
                        data.push({
                            x: time + i * 1000,
                            y: 0
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

