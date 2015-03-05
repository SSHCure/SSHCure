
var plot_attack = function(attack_id) {
    
    // Update attack profile plot
    //$('#attack-profile-plot').setPlotLoading();
    
    // TODO refactor:
    attack_ID = attack_id;

    var attack_profile_scan_data = new Array();
    attack_profile_scan_data['label'] = "Scan";
    attack_profile_scan_data['color'] = "rgb(26, 150, 212)";
    attack_profile_scan_data['data'] = [];
    
    var attack_profile_bruteforce_data = new Array();
    attack_profile_bruteforce_data['label'] = "Brute-force";
    attack_profile_bruteforce_data['color'] = "rgb(250, 100, 45)";
    attack_profile_bruteforce_data['data'] = [];
    
    var attack_profile_dieoff_data = new Array();
    attack_profile_dieoff_data['label'] = "Compromise";
    attack_profile_dieoff_data['color'] = "rgb(220, 0, 8)";
    attack_profile_dieoff_data['data'] = [];


    // Scan attacks
    //$.each(data.data.scan, function (time, attacks) {
    //    plot_scan_data['data'].push([time * 1000, attacks]);
    //});

    //// Brute-force attacks
    //$.each(data.data.bruteforce, function (time, attacks) {
    //    plot_bruteforce_data['data'].push([time * 1000, attacks]);
    //});
    //
    //// Compromise attacks
    //$.each(data.data.compromise, function (time, attacks) {
    //    plot_compromise_data['data'].push([time * 1000, attacks]);
    //});



    
    $.getJSON(('json/data/get_attack_graph.php'), { 'attack_id': attack_ID, 'timezone_offset': (new Date()).getTimezoneOffset() }, function(json) {
        var time_min = json.meta.time_min;
        var time_max = json.meta.time_max;
        var ip_min = json.meta.ip_min;
        var ip_max = json.meta.ip_max;
        
        $.each(json.data.scan, function() {
            attack_profile_scan_data['data'].push(this);
        });
        $.each(json.data.bruteforce, function() {
            attack_profile_bruteforce_data['data'].push(this);
        });
        $.each(json.data.dieoff, function() {
            attack_profile_dieoff_data['data'].push(this);
        });
        
        var total_points = attack_profile_scan_data['data'].length
                + attack_profile_bruteforce_data['data'].length
                + attack_profile_dieoff_data['data'].length;
        
        if (total_points == 0) {
            $('#attack-profile-plot').css('visibility', 'hidden');
            return true;
        }
        
        // Determine x-axis range
        var xaxis_min, xaxis_max;
        if (time_max - time_min < 500) { // 500 ms
            xaxis_min = time_min - 1000;
            xaxis_max = time_max + 1000;
        } else if (ip_min == ip_max) {
            var time_delta = time_max - time_min;
            xaxis_min = time_min - time_delta;
            xaxis_max = time_max + time_delta;
        } else {
            xaxis_min = null;
            xaxis_max = null;
        }
        
        // Determine y-axis range
        var yaxis_min, yaxis_max;
        if (ip_min == ip_max) {
            yaxis_min = -1;
            yaxis_max = 1;
        } else if (ip_max - ip_min < 3) {
            yaxis_min = 0;
            yaxis_max = 3;
        } else if (total_points < 5 && ip_max - ip_min > 1000) {
            yaxis_min = 0;
            yaxis_max = (ip_max - ip_min) * 1.05;
        } else {
            console.log("Else");
            yaxis_min = 0;
            yaxis_max = ip_max - ip_min;
        }
        
        var log_threshold = 100000;
        var use_log_yaxis = (yaxis_max > log_threshold);
        
        // Determine ticks
        if (use_log_yaxis) {
            var log_yaxis_ticks = [ 1, 10, 100, 1000, 10000, 100000 ];
            if (yaxis_max > 100000) {
                log_yaxis_ticks.push(1000000);
            }
            if (yaxis_max > 1000000) {
                log_yaxis_ticks.push(10000000);
            }
        }
        
        var xTickLength;
        if (ip_min == ip_max) {
            xTickLength = 0;
        } else {
            xTickLength = null;
        }

        xTickLength = 0;
        
        
        var time_format, min_tick_size;
        if (time_max - time_min < 30 * 1000) {
            time_format = "%H:%M:%S";
            min_tick_size = [1, "second"];
        } else if (time_max - time_min < 60 * 1000) {
            time_format = "%H:%M:%S";
            min_tick_size = [10, "second"];
        } else if (time_max - time_min < 120 * 1000) {
            time_format = "%H:%M:%S";
            min_tick_size = [30, "second"];
        } else {
            time_format = "%H:%M";
            min_tick_size = [1, "minute"];
        }
        
        var graph_options = {
            lines: {    show: false },
            points: {   show: true, 
                        radius: 3 },
            grid: {     hoverable: true, 
                        clickable: true,
                        borderWidth: {top: 0, right: 0, left: 0, bottom:1}},
                        color: '#aaa',
                        minBorderMargin: 100,
            series: {   downsample: {
                            threshold: 1000 }
                        },
            alegend: {   position: "ne",
                        noColumns: 4,
                        margin: [5, 2], // [x-margin, y-margin]
                        labelFormatter: function(label, series) {
                            return "<span style=\"padding-right: 3px;\">" + label + '</span>';
                        }},
            legend: {
                container: $('#attacks-plot-legend'),
                noColumns: 3,
                labelFormatter: function (label, series) {
                    return "<span>" + label + '</span>';
                }
            },
            xaxis: {    min: xaxis_min, 
                        max: xaxis_max,
                        tickLength: xTickLength,
                        mode: "time", 
                        timeformat: time_format, 
                        ticks: 5, 
                        minTickSize: min_tick_size },
            yaxis: {    min: (use_log_yaxis) ? null : yaxis_min, 
                        max: (use_log_yaxis) ? null : yaxis_max,
                        tickLength: 0,
                        tickFormatter: function formatter(v, axis) {
                            if (use_log_yaxis) return v;
                            else if (ip_min == ip_max) return '';
                            else if (v / 100000000 >= 1) return v.toString().substr(0, 3) + 'M';
                            else if (v / 10000000 >= 1) return v.toString().substr(0, 2) + 'M';
                            else if (v / 1000000 >= 1) return v.toString().substr(0, 1) + 'M';
                            else if (v / 100000 >= 1) return v.toString().substr(0, 3) + 'k';
                            else if (v / 10000 >= 1) return v.toString().substr(0, 2) + 'k';
                            else if (v / 1000 >= 1) return v.toString().substr(0, 1) + 'k';
                            else return v.toFixed(axis.tickDecimals);
                        },
                        ticks: (use_log_yaxis) ? log_yaxis_ticks : null,
                        transform: function (v) {
                            if (use_log_yaxis) {
                                return Math.log(v + 1) / Math.LN10;
                            } else {
                                return v;
                            }
                        },
                        inverseTransform: function (v) {
                            if (use_log_yaxis) {
                                return Math.pow(10, v) - 1;
                            } else {
                                return v;
                            }
                        }
                    }
        };
        
        // Merge all datasets
        var data = [];
        if (attack_profile_scan_data['data'].length != 0) data.push(attack_profile_scan_data);
        if (attack_profile_bruteforce_data['data'].length != 0) data.push(attack_profile_bruteforce_data);
        if (attack_profile_dieoff_data['data'].length != 0) data.push(attack_profile_dieoff_data);
        
        // Plot
        var plot = $.plot($('#attack-profile-plot'), data, graph_options);
        
        // Find out whether a network-wide L3 block has occurred
        var blocking_time = $('#attack-info-table td.property:contains("blocking_time")').next().text();
        if (blocking_time != '') { // Block detected
            blocking_time *= 1000; // Convert timestamp to ms
            
            // Fix time zone offset
            var timezone_offset = (new Date()).getTimezoneOffset();
            blocking_time += (-1 * timezone_offset * 60 * 1000);
            
            // Check whether the attack blocking time is close (90%) to the end of the attack. If so, increase the x-axis range of the attack profile plot.
            var xaxis_range = plot.getAxes().xaxis.max - plot.getAxes().xaxis.min;
            if (blocking_time > (xaxis_range * 0.95) + plot.getAxes().xaxis.min) {
                graph_options['xaxis']['max'] = plot.getAxes().xaxis.min + (1.05 * xaxis_range);
            }
            
            // Change legend position
            graph_options['legend']['position'] = "nw";
            
            var blocking_data = {
                data:       [ [ blocking_time, plot.getAxes().yaxis.min ], [ blocking_time, plot.getAxes().yaxis.max ] ],
                color:      "#000",
                label:      "Network-wide L3 block",
                lines: {    show: false },
                points: {   show: false },
                dashes: {   show: true,
                            lineWidth: 1 }
            };
            
            data.push(blocking_data);
            
            // Replot, including blocking data
            plot = $.plot($('#attack-profile-plot'), data, graph_options);
        }
        
        // Tooltip
        var hovered_point = -1;
        $('#attack-profile-plot').bind('plothover', function (event, pos, item) {
            if (!item && hovered_point != -1) {
                hovered_point = -1;
            }
            
            if (item && item.datapoint[1] != hovered_point) {
                hovered_point = item.datapoint[1];
                
                var tooltip_contents = "";
                if (item.series.label == "Network-wide L3 block") {
                    showTooltip(item.pageX, item.pageY, "Network-wide L3 block");
                } else {
                    var hover_ip = decodeIPNumber(item.datapoint[1] + ip_min);
                    var phase_color;
                    
                    if (item.series.label == "Scan") {
                        phase_color = "rgb(0, 0, 0)";
                    } else {
                        phase_color = item.series.color;
                    }
                    
                    showTooltip(item.pageX, item.pageY, "IP address: " + hover_ip + "<br>Phase: <span style='color: " + phase_color + "'>" + item.series.label + "</span>");
                }
            } else if (!item) {
                $('#tooltip').remove();
            }
        }).bind('plotclick', function (event, pos, item) {
            var hover_ip = item.datapoint[1] + ip_min;
            var url = SSHCure.urlForAction('host', {'id': hover_ip});
            SSHCure.showLoadingDialog();
            window.location.assign(url);
        });
    });
    
    //TODO get flows back in the new 'Targets' section
    //$.getJSON(SSHCure.urlForAction('data/attackflow'), {
    //        'attack_ID':        attack_ID
    //}, function(json) {
    //    if (json.error == 0) { // Success
    //        loadAttackFlowInfo(json.flows);
    //    }
    //});
    

}
/*
    // Retrieve attack targets
    var compromise_ports = {}; // Contains mappings from compromised hosts to the port numbers associated with the compromise
    $.getJSON(SSHCure.urlForAction('data/attacktargets'), {'id': attack_ID}, function(data, textStatus, jqXHR) {
        var tableData = (data && data['table'] ? data['table'] : {'header':['could not load data'], 'data':[]} );
        
        // Add the port numbers associated with compromises to the compromise_ports array
        $.each(tableData.data, function () {
            if (this.comp_on) compromise_ports[this.host] = this.compromise_ports;
        });
        
        // Total number of targets of an attack
        var expected_targets = parseInt($('div#expected_targets').text());
        
        // If less targets are visible than expected, this is because there are 'expired' targets (cleanup by backend)
        if (tableData.data.length != expected_targets && tableData.data.length != SSHCure.getConfig('targets.maxnumber')) {
            $('#attack-targets-expiration-warning').show();
        }
        
        $('#tblTargets').fillTable(tableData, SSHCure.urlForAction('host', {'id': '##'}), 'id');
        
        // Only proceed if 'Targets' table actually contains data
        if ($('table#tblTargets tr:nth-child(2)').attr('class').indexOf('nodata') == -1) {
            // Remove row-based hover event and click event
            $('table#tblTargets tr').unbind('mouseenter mouseleave');
        
            // Add hover event to first column ('Target')
            $('table#tblTargets tr[class*=data] td:first-child').hover(function() {
                $(this).addClass('hover');
            },function() {
                $(this).removeClass('hover')
            });
            
            var last_target_ID = -1; // ID of target of which the flow data has been selected lastly
        
            // Add hover event to third column ('Show flow data')
            $('table#tblTargets tr[class*=data] td:nth-child(4)').hover(function() {
                    $(this).addClass('hover');
                },function() {
                    $(this).removeClass('hover')
                }).click(function(event) {
                    // Prevent the event from bubbling up the DOM tree, because the page will navigate to Host Details otherwise
                    event.stopPropagation();
                    
                    // Unset current table cell (class 'current')
                    $('table#tblTargets tr[class*=data] td.current').removeClass('current');
                    
                    // Select the row that has been clicked
                    var row;
                    if ($(event.target).hasClass('ui-icon')) { // Icon has been clicked
                        row = $(event.target).parent();
                    } else {
                        row = $(event.target);
                    }
                    
                    // Determine target ID
                    var target_ID = '';
                    $.each(row.parent().attr('class').split(' '), function() {
                        if (this.substr(0, 3) == 'id-') {
                            target_ID = this.substr(3);
                            return false;
                        }
                    });
                    
                    // Highlight currently selected 'Show flow data' cell
                    row.addClass('current');
                    
                    // Flow data only needs to be loaded when another (not the same!) target has been selected
                    if (target_ID != last_target_ID) {
                        last_target_ID = target_ID;
                        
                        // Show processing message in flow data table
                        $('#flow-data-table').setTableLoading();
                        
                        $.getJSON(SSHCure.urlForAction('data/attackflow'), {
                                'attack_ID':        attack_ID,
                                'target_ID':        target_ID,
                                'start_time':       $('table#attack-info-table td.property:contains(\'start_time_unix\') ~ td.value').text(),
                                'end_time':         $('table#attack-info-table td.property:contains(\'end_time_unix\') ~ td.value').text(),
                                'attacker_IP':      $('table#attack-info-table td.property:contains(\'attacker_ip_dec\') ~ td.value').text()
                            }, function(json) {
                                showFlowTable(json.flows);
                                
                                // Highlight flow records with port numbers associated to a compromise, if available
                                if (target_ID in compromise_ports && compromise_ports[target_ID] != '') {
                                    var ports = compromise_ports[target_ID]; // Contains comma-separated list of port numbers
                                    ports = ports.split(",");
                                    
                                    $.each(ports, function () {
                                        $('#flow-data-table tr:has(td:contains(:' + this + '))').addClass('compromise-row');
                                        $('#flow-data-table tr.compromise-row').css('color', 'white').css('background-color', '#FC6666');
                                    });
                                }
                        });
                    }
                }
            );
        }
    });
}
*/
var showTooltip = function(x, y, contents) {
    if ($('#tooltip').length > 0) {
        $('#tooltip').remove();
    }
    
    $('<div id=\"tooltip\">' + contents + '</div>').css( {
        position: 'absolute',
        display: 'none',
        top: y + 5,
        left: x + 5,
        border: '1px solid #fdd',
        padding: '2px',
        opacity: 0.80,
        'background-color': '#fee',
        'text-align': 'left'
    }).appendTo('body').fadeIn(200);
}

var decodeIPNumber = function(number) {
    var address = number % 256;
    for (var i = 3; i > 0; i--) {
        number = Math.floor(number / 256);
        address = number % 256 + '.' + address;
    }
    return address;
}

var loadAttackFlowInfo = function(data) {
    var el_table = $('#attack-info-table');
    
    var ir = {
        'Total flows' : (data.info['total flows'] == 10000 ? '10000+' : data.info['total flows'])
    ,   'Total packets' : data.info['total packets']
    ,   'Total bytes' : data.info['total bytes']
    };
    
    $.each(ir,function(key,val) {
        var el_tr = $('<tr />');
        
        el_tr.append($('<td />',{'class':'property'}).text(key));
        el_tr.append($('<td />',{'class':'value'}).text(val));
        
        el_table.append(el_tr);
    });
};

var showFlowTable = function(data, header) {
    header = header || "Flow data";
    var el_header = $('<h2 />').text(header);

    var el_table = $('<table />').addClass('list');
    el_table.attr('id', 'flow-data-table');
        
    var el_tr, el_td;
    
    if (data.data.length == 0) { // An error occurred during nfdump data retrieval
        el_tr = $('<tr />', { 'class':'info' });
        el_td = $('<td />').text("The flow data cannot be shown, as it is not available on your machine anymore...");
        el_tr.append(el_td);
        el_table.append(el_tr);
    } else {
        el_tr = $('<tr />', { 'class':'header' });
        el_tr.append($('<th />').text('Start'));
        el_tr.append($('<th />').text('Duration'));
        el_tr.append($('<th />').text('Source'));
        el_tr.append($('<th />').text('Destination'));
        el_tr.append($('<th />').text('Flags'));
        el_tr.append($('<th />').text('Packets'));
        el_tr.append($('<th />').text('Bytes'));
        el_table.append(el_tr);
    
        $.each(data.data, function () {
            var ds = new Date(this.start_time * 1000);
            var de = new Date(this.end_time * 1000);
            var from_attacker = (this.source_ip == data.attacker);
        
            el_tr = $('<tr />', {'class':'flow'});
        
            el_tr.addClass('data');
            el_tr.addClass(from_attacker ? 'odd' : 'even');
        
            // Start time
            el_td = $('<td />').text(('' + ds.getHours()).lpad('0', 2) + ':' + ('' + ds.getMinutes()).lpad('0', 2) + ':' + ('' + ds.getSeconds()).lpad('0', 2));
            el_tr.append(el_td);
        
            el_td = $('<td />').text(this.duration);
            el_tr.append(el_td);
        
            el_td = $('<td />').text(this.source_ip + ":" + this.source_port);
            el_tr.append(el_td);
            
            el_td = $('<td />').text(this.destination_ip + ":" + this.destination_port);
            el_tr.append(el_td);
        
            el_td = $('<td />').text(this.flags);
            el_tr.append(el_td);
        
            el_td = $('<td />').text(this.packets);
            el_tr.append(el_td);
            
            el_td = $('<td />').text(this.bytes);
            el_tr.append(el_td);
        
            el_table.append(el_tr);
        });
    }
    
    var el_table_div = $('<div />', { 'class':'table' });
    el_table_div.append(el_table);
    
    $('#attack-flow-data').empty().append(el_header).append(el_table_div).show();
    
    var current_compromise_row = -1;
    $('h2:contains(\"Flow data\")').click(function () {
        var compromise_rows = $('#flow-data-table tr.compromise-row').length; // Contains all rows in the flow data table that beloging to a compromise_port (as jQuery object)
        
        // Only proceed when there are table rows showing compromise traffic
        if ($('#flow-data-table tr.compromise-row').length > 0) {
            current_compromise_row = (current_compromise_row + 1) % compromise_rows;
            $('#flow-data-table tr.compromise-row').eq(current_compromise_row).ScrollTo();
        }
    });
};
