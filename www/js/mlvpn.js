var url = "http://localhost:1040/status";

function json_refresh(json)
{
    console.log(json);
    var tuntap = $('#tuntap');

    var tunnels = $('<div>');
    for (var i = 0; i < json.tunnels.length; i++)
    {
        var tun = json.tunnels[i];
        var tundiv = $('<div>');
        tundiv.addClass("tun well");
        tundiv.append($('<button class="btn btn-medium btn-success" style="width: 300px;">'+tun.name+'</button>'));
        tunnels.append(tundiv);
    }
    tuntap.html(tunnels);
}

$().ready(function()
{
    $.getJSON(url,
        json_refresh,
        function(json) {
            alert("Error: "+x);
        }
    );
});

