
var Dashboard = function () {
    var me = this;

    me.initialize = function () {
        add_time_window_control_listeners();
        plot_incoming_attacks_plot();
        load_incoming_attacks_table();
    };

    return me;
};

function add_time_window_control_listeners () {
    // Select 'Week' as default, i.e., if none has been selected
    if ($('.btn.active').length == 0) {
        $('.btn:contains(\"Week\")').addClass('active');
    }

    // General button handling
    $('.btn-group .btn').click(function () {
        // Check which button was selected before
        var prev_button_text = $('.btn-group .btn.active').text();

        // Do nothing if the already active button was clicked
        if ($(this).text() == prev_button_text) return;

        // Remove 'active' class from previously selected item(s)
        $('.btn-group .btn').removeClass('active');

        // Add 'active' class to newly selected item
        $(this).addClass('active');

        // Show loading message
        $('#incoming-attacks-plot ~ div.loading').show();
        $('#incoming-attacks-plot-header').hide();
        $('#incoming-attacks-plot').hide();

        // Replot 'incoming attacks' plot based on newly selected time window
        plot_incoming_attacks_plot($(this).text().toLowerCase());
    });
}

function load_incoming_attacks_table (period) {
    var url = "json/get_incoming_attacks_data.php";
    var params = {
    };

    $.getJSON(url, params, function (data, textStatus, jqXHR) {
        var table = $('<table>');
        var head = $('<thead>');
        var body = $('<tbody>');
        head.append(
            $('<td>').text('Phases'),
            $('<td>').text('Active'),
            $('<td>').text('Attacker'),
            $('<td>').text('Start time'),
            $('<td>').text('Targets')
        ).appendTo(head);

        $.each(data.data, function () {
            var phases = $('<div>').addClass('phases').append(
                $('<div>').addClass('phase scan'),
                $('<div>').addClass('phase bruteforce'),
                $('<div>').addClass('phase compromise')
            );
            
            if (jQuery.inArray(this.certainty, [ 0.25, 0.5, 0.75 ])) {
                phases.find('div.phase.scan').addClass('on');
            }
            if (jQuery.inArray(this.certainty, [ 0.4, 0.5 ])) {
                phases.find('div.phase.bruteforce').addClass('on');
            }
            if (jQuery.inArray(this.certainty, [ 0.65, 0.75 ])) {
                phases.find('div.phase.compromise').addClass('on');
            }

            $('<tr>').append(
                $('<td>').append(phases),
                $('<td>').html("<span class=\"glyphicon glyphicon-flash\"></span>"),
                $('<td>').text(this.attacker),
                $('<td>').text(this.start_time),
                $('<td>').text(this.target_count)
            ).appendTo(body);
        });
        head.appendTo(table);
        body.appendTo(table);

        // Hide loading message and show divs related to plot
        $('#incoming-attacks-table ~ div.loading').hide();
        $('#incoming-attacks-table').show();

        table.appendTo($('#incoming-attacks-table'));
    });
}

function plot_incoming_attacks_plot (period) {
    if (typeof(period) === 'undefined') {
        period = 'week';
    }
    
    var url = "json/get_incoming_attacks_plot_data.php";
    var now = parseInt((new Date().getTime()) / 1000);
    var max_start_time = now;

    var min_start_time;
    if (period == 'day') {
        min_start_time = now - (24 * 60 * 60);
    } else if (period == 'month') {
        min_start_time = now - (30 * 24 * 60 * 60);
    } else {
        min_start_time = now - (7 * 24 * 60 * 60);
    }

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
                clickable: true,
                borderWidth: 0
            },
            series: {
                stack: true
            },
            legend: {
                container: $('#incoming-attacks-plot-legend'),
                noColumns: 3,
                labelFormatter: function (label, series) {
                    return "<span>" + label + '</span>';
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
                },
                tickLength: 0
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
