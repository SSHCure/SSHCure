
Dashboard = function () {
    this.internal_networks = "";

    this.initialize = function () {
        // Retrieve internal domains
        var url = "json/rpc/get_internal_networks.php";
        var params = {};
        $.getJSON(url, params, function (data, textStatus, jqXHR) {
            internal_networks = data;
            add_time_window_control_listeners();
            plot_incoming_attacks_plot(internal_networks);
            load_attacks_table(INCOMING, internal_networks);
            load_attacks_table(OUTGOING, internal_networks);
            load_top_targets_table(COMPROMISE);
            load_top_targets_table(BRUTEFORCE);
        });
    };

    return this;
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
        $('#attacks-plot ~ div.loading').show();
        $('#attacks-plot-header').hide();
        $('#attacks-plot').hide();

        // Replot 'incoming attacks' plot based on newly selected time window
        plot_incoming_attacks_plot($(this).text().toLowerCase());
    });
}

function load_attacks_table (type, internal_networks, period) {
    var url;

    if (type == INCOMING) {
        url = "json/data/get_incoming_attacks.php";
    } else {
        url = "json/data/get_outgoing_attacks.php";
    }

    var params = {
        'internal_networks': internal_networks
    };

    $.getJSON(url, params, function (data, textStatus, jqXHR) {
        var table = $('<table>').addClass('list');
        var head = $('<thead>');
        var body = $('<tbody>');
        head.append(
            $('<td>').text('Phases'),
            $('<td>').text('Active'),
            $('<td>').text('Attacker'),
            $('<td>').text('Start time'),
            $('<td>').text('Targets')
        ).appendTo(head);

        if (data.data.length == 0) {
            $('<tr>').append(
                $('<td colspan="5" style="font-style: italic;">').text("No data available...")
            ).appendTo(body);
        } else {
            $.each(data.data, function () {
                var phases = $('<div>').addClass('phases').append(
                    $('<div>').addClass('phase scan'),
                    $('<div>').addClass('phase bruteforce'),
                    $('<div>').addClass('phase compromise')
                );
                var this_attack = this;
                // Phases
                if (jQuery.inArray(this.certainty, [ 0.25, 0.5, 0.75 ])) {
                    phases.find('div.phase.scan').addClass('on');
                }
                if (jQuery.inArray(this.certainty, [ 0.4, 0.5, 0.65, 0.75 ])) {
                    phases.find('div.phase.bruteforce').addClass('on');
                }
                if (jQuery.inArray(this.certainty, [ 0.65, 0.75 ])) {
                    phases.find('div.phase.compromise').addClass('on');
                }

                // Date
                var date = new Date(this.start_time * 1000);

                var tr = $('<tr>').append(
                    $('<td>').append(phases),
                    $('<td>').html("<span class=\"glyphicon glyphicon-flash\"></span>"),
                    $('<td>').append($('<a>')
                            .addClass('ip-addr')
                            //.attr('href', '#')
                            .text(this.attacker)
                            .click(function () {
                                var url = "json/html/get_host_details.php";
                                var params = {
                                    'host': $(this).text()
                                }
                                $.getJSON(url, params, function (data, textStatus, jqXHR) {
                                    // Overwrite modal title using Javascript, since Bootstrap uses a completely different element for modal headers and bodies
                                    $('#host-details h4.modal-title').text("Host details for " + params['host']);

                                    // Insert pre-rendered HTML into body
                                    $('#host-details div.modal-body').html(data.data);
                                    $('#host-details').modal({
                                        show: true
                                    });
                                });
                            })),
                    $('<td>').text(date.toString("ddd. MMM d, yyyy HH:mm")),
                    $('<td>').text(this.target_count)
                ).appendTo(body);
                tr.click(function () {
                    var url = "json/data/get_attack_details.php";
                    var params = {
                        'attack_id': this_attack.attack_id
                    }
                    $.getJSON(url, params, function(data) {
                        //TODO parse json, create Attack details stuff
                        $('#attack-details-content').text(data.data[0]);
                    });
                    url = "json/data/get_targets_for_attack.php";
                    $.getJSON(url, params, function(data) {
                        //TODO parse json, create Targets table
                        $('#incoming-targets-content').text(""+data.data.length);
                    });
                    url = "json/data/get_attack_graph.php";
                    params['timezone_offset'] = (new Date()).getTimezoneOffset();
                    $.getJSON(url, params, function(data) {
                        //TODO parse json, plot using flot
                    });
                });
            });
        }
        
        head.appendTo(table);
        body.appendTo(table);

        if (type == INCOMING) {
            // Hide loading message and show divs related to plot
            $('#incoming-attacks-table ~ div.loading').hide();
            $('#incoming-attacks-table').show();
            table.appendTo($('#incoming-attacks-table'));
        } else {
            // Hide loading message and show divs related to plot
            $('#outgoing-attacks-table ~ div.loading').hide();
            $('#outgoing-attacks-table').show();
            table.appendTo($('#outgoing-attacks-table'));
        }
    });
}

function load_top_targets_table (type) {
    var url;

    if (type == BRUTEFORCE) {
        url = "json/data/get_top_targets_bruteforce.php";
    } else {
        url = "json/data/get_top_targets_compromise.php";
    }

    var params = {};

    $.getJSON(url, params, function (data, textStatus, jqXHR) {
        var table = $('<table>').addClass('list');
        var head = $('<thead>');
        var body = $('<tbody>');
        head.append(
            $('<td>').text('Target'),
            $('<td>').text('Attacks'),
            $('<td>').text('Compromises')
        ).appendTo(head);

        if (data.data.length == 0) {
            $('<tr>').append(
                $('<td colspan="5" style="font-style: italic;">').text("No data available...")
            ).appendTo(body);
        } else {
            $.each(data.data, function () {
                $('<tr>').append(
                    $('<td>').append($('<a>')
                        .addClass('ip-addr')
                        .attr('href', '#')
                        .text(this.target))
                        .click(function () {
                            var url = "json/html/get_host_details.php";
                            var params = {
                                'host': $(this).text()
                            }
                            $.getJSON(url, params, function (data, textStatus, jqXHR) {
                                // Overwrite modal title using Javascript, since Bootstrap uses a completely different element for modal headers and bodies
                                $('#host-details h4.modal-title').text("Host details for " + params['host']);

                                // Insert pre-rendered HTML into body
                                $('#host-details div.modal-body').html(data.data);
                                $('#host-details').modal({
                                    show: true
                                });
                            });
                        }),
                    $('<td>').text(this.attack_count),
                    $('<td>').text(this.compromise_count)
                ).appendTo(body);
            });
        }
        
        head.appendTo(table);
        body.appendTo(table);

        if (type == BRUTEFORCE) {
            // Hide loading message and show divs related to plot
            $('#top-targets-bruteforce-table ~ div.loading').hide();
            $('#top-targets-bruteforce-table').show();
            table.appendTo($('#top-targets-bruteforce-table'));
        } else {
            // Hide loading message and show divs related to plot
            $('#top-targets-compromise-table ~ div.loading').hide();
            $('#top-targets-compromise-table').show();
            table.appendTo($('#top-targets-compromise-table'));
        }
    });
}

function plot_incoming_attacks_plot (internal_networks, period) {
    if (typeof(period) === 'undefined') {
        period = 'week';
    }
    
    var url = "json/data/get_incoming_attacks_plot.php";
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
                container: $('#attacks-plot-legend'),
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
                        var months = [ "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ];
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
        $('#attacks-plot ~ div.loading').hide();
        $('#attacks-plot-header').show();
        $('#attacks-plot').show();
        
        $.plot($('#attacks-plot'),
                [ plot_scan_data, plot_bruteforce_data, plot_compromise_data ], options);
    });
}

// Constants
var BRUTEFORCE = 1;
var COMPROMISE = 2;
var INCOMING = 1;
var OUTGOING = 2;
