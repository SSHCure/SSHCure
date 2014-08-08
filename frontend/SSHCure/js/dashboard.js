
var Dashboard = function () {
    var me = this;

    me.initialize = function () {
        plot_incoming_attacks_plot();
    };

    return me;
};

function plot_incoming_attacks_plot () {
    var url = "json/get_incoming_attacks_data.php";
    var now = parseInt((new Date().getTime()) / 1000);
    var min_start_time = now - (7 * 24 * 60 * 60);
    var max_start_time = now;
    var params = {
        'min_start_time': min_start_time, // Go 7 days back in time
        'max_start_time': max_start_time
    };

    $.getJSON(url, params, function (data, textStatus, jqXHR) {
        // Scan attacks
        var plot_scan_data = new Array();
        plot_scan_data['label'] = "Scan";
        plot_scan_data['color'] = "rgb(26, 150, 212)";
        plot_scan_data['data'] = new Array();
        $.each(data.data.scan, function (time, attacks) {
            plot_scan_data['data'].push([time * 1000, attacks]);
        });

        // Brute-force attacks
        var plot_bruteforce_data = new Array();
        plot_bruteforce_data['label'] = "Brute-force";
        plot_bruteforce_data['color'] = "rgb(250, 100, 45)";
        plot_bruteforce_data['data'] = new Array();
        $.each(data.data.bruteforce, function (time, attacks) {
            plot_bruteforce_data['data'].push([time * 1000, attacks]);
        });
        
        // Compromise attacks
        var plot_compromise_data = new Array();
        plot_compromise_data['label'] = "Compromise";
        plot_compromise_data['color'] = "rgb(220, 0, 8)";
        plot_compromise_data['data'] = new Array();
        $.each(data.data.compromise, function (time, attacks) {
            plot_compromise_data['data'].push([time * 1000, attacks]);
        });

        var last_day = -1;
        var options = {
            bars: {
                backgroundColor: null,
                show: true
            },
            lines: {
                show: false,
                steps: false
            },
            grid: {
                hoverable: true, 
                clickable: true
            },
            series: {
                stack: true
            },
            legend: {
            //     position: "nw",
                container: $('#incoming-attacks-plot-legend'),
                noColumns: 3,
                // margin: [ 5, 2 ], // [x-margin, y-margin]
                labelFormatter: function (label, series) {
                    return "<span style=\"margin-left: 3px; margin-right: 10px;\">" + label + '</span>';
                }
            },
            xaxis: {
                mode: "time",
                min: min_start_time * 1000, 
                max: max_start_time * 1000,
                twelveHourClock : false,
                tickFormatter: function (val, axis) {
                    var date = new Date();
                    date.setTime(val);
                    var label = "";
                    var week = (max_start_time - min_start_time >= 604800);
                    
                    // 'date > Dashboard.getStartTime()' is there to make sure that selected date is actually visible
                    if (date.getDate() != last_day && date > min_start_time * 1000) {
                        last_day = date.getDate();
                        var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                        label += date.getDate() + " " + months[date.getMonth()];
                        
                        if (!week) {
                            label += ",<br />";
                        }
                    }
                    
                    if (!week) {
                        var minutes = date.getMinutes();
                        if (minutes < 10) {
                            minutes = "0" + minutes;
                        }
                        label += date.getHours() + ":" + minutes;
                    }
                    
                    return label;
                }
            },
            yaxis: {
                min: 0,
                minTickSize: 1,
                tickDecimals: 0
            }
        };

        // Hide loading message and show divs related to plot
        $('#incoming-attacks-plot ~ div.loading').hide();
        $('#incoming-attacks-plot-header').show();
        $('#incoming-attacks-plot').show();
        
        $.plot($('#incoming-attacks-plot'),
                [ plot_scan_data, plot_bruteforce_data, plot_compromise_data ], options);
    });
}

$(window).load(function () {
    Dashboard = new Dashboard();
    Dashboard.initialize();
});