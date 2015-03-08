var d;
var loadPage = function(href, replaceState) {
    if (!href.match(/index\.php\?(.*)$/)){
        // something is wrong, we expect index.php urls 
        console.log("invalid URL, expecting index.php?...");
        return;
    }
    queryString  = RegExp.$1;
    replaceState = typeof replaceState !== 'undefined' ? replaceState : false;
    
    // Only push if the page is different from the previous(== current) one
    pushState = !(window.history.state && window.history.state.href === href);

    action      = $.parseQuery(queryString).action;
    new_title   = "SSHCure | " + action; // TODO capitalize 

    attack_id = $.parseQuery(queryString).attack_id;


    // TODO: when we get the more complex links (filter_range etc)
    // we should only save those query params that matter for comparison
    if (replaceState) {
        window.history.replaceState({href: href}, new_title, href);
    } else if(pushState) {
        window.history.pushState({href: href}, new_title, href);
    }

    $('div#main').load("index.php?action=" + action + "&block=main", function() {
        // Update the active button on the navigation bar
        $('.nav-sidebar li').removeClass('active');
        $('.nav-sidebar li a[href="index.php?action='+action+'"]').parent().addClass('active')

        // This switch functions as a $(document).ready for asynchronous page loads
        if (typeof d !== 'object') {
            // 'd' should be some sort of stateful thing
            // containing all the stuff we need across the different sections
            d = new Dashboard();
        }
        switch (action) {
            case "dashboard":
                d.initialize();
                break;
            case "incoming":
                load_attacks_table(INCOMING);
                loadAttackDetails(href);
                loadAttackTargets(href);
                break;
            case "outgoing":
                console.log("loading outgoing page");
                load_attacks_table(OUTGOING);
                loadAttackDetails(href);
                loadAttackTargets(href);
                break;
            case "search":
                console.log("loaded search page");
                initialize_search();
                break;
            case "status":
                initialize_status();
        }
    });
}

var loadAttackDetails = function(href) {
    //href = e.data('href');
    console.log("loadAttackDetails data.href: " + href)
    if (!href.match(/index\.php\?(.*)$/)){
        // something is wrong, we expect index.php urls 
        console.log("invalid URL, expecting index.php?...");
        return;
    }
    queryString  = RegExp.$1;
    // get needed vars from query string
    attack_id      = $.parseQuery(queryString).attack_id;
    if (typeof attack_id == 'undefined') {
        console.log("No attack_id, aborting loadAttackDetails");    
        return;
    }
    console.log("loadAttackDetails attack_id: " + attack_id);
    // update State
    replaceState = typeof replaceState !== 'undefined' ? replaceState : false;
    pushState = !(window.history.state && window.history.state.href === href);

    // fetch stuff via AJAX (so bind this function in dashboard.js)(
    var url = "json/html/get_attack_details.php";
    var params = {
        'attack_id': attack_id
    }
    $.getJSON(url, params, function(data) {
        $('#attack-details').html(data.data);
        plot_attack(attack_id);
        loadAttackStatistics(attack_id);
    });
    console.log("filled #attack-details");
    if (replaceState) {
        window.history.replaceState({href: href}, new_title, href);
    } else if(pushState) {
        window.history.pushState({href: href}, new_title, href);
    }

    // Plot
    //url = "json/data/get_attack_graph.php";
    //params['timezone_offset'] = (new Date()).getTimezoneOffset();
    //$.getJSON(url, params, function(data) {
    //    //TODO parse json, create Attack details stuff
    //    console.log(data);
    //    $('#attack-details-graph').plot([ data.plot_scan_data, data.plot_bruteforce_data, data.plot_compromise_data ]);
    //});
   // plot_attack(attack_id);
}

var loadAttackStatistics = function(attack_id) {
    var url = "json/rpc/get_attack_flows.php";
    var params = {
        'attack_id': attack_id,
    }
    $.getJSON(url, params, function(data) {
        console.log("got attack statistics");
        console.log(data.flows.info);
        $('#attack-details-flows').html(data.flows.info['total flows']);
        $('#attack-details-bytes').html(data.flows.info['total bytes']);
        $('#attack-details-packets').html(data.flows.info['total packets']);
    });
}

var loadAttackTargets = function(href) {
    //href = e.data('href');
    console.log("loadAttackTargets data.href: " + href)
    if (!href.match(/index\.php\?(.*)$/)){
        // something is wrong, we expect index.php urls 
        console.log("invalid URL, expecting index.php?...");
        return;
    }
    queryString  = RegExp.$1;
    // get needed vars from query string
    attack_id      = $.parseQuery(queryString).attack_id;
    if (typeof attack_id == 'undefined') {
        console.log("No attack_id, aborting loadAttackTargets");    
        return;
    }
    console.log("loadAttackTargets attack_id: " + attack_id);
    // update State
    replaceState = typeof replaceState !== 'undefined' ? replaceState : false;
    pushState = !(window.history.state && window.history.state.href === href);

    // fetch stuff via AJAX (so bind this function in dashboard.js)(
    var url = "json/html/get_targets_for_attack.php";
    var params = {
        'attack_id': attack_id
    }
    //$.getJSON(url, params, function(data) {
    //    $('#attack-details').html(data.data);
    //});
    $.getJSON(url, params, function(data) {
        $('#incoming-targets-content').html(data.data);
        $('#incoming-targets').show();
        $('#incoming-targets #target-table tr').click(function(){
            loadFlowData($(this).data('href'));
            $(this).addClass("selected").siblings().removeClass("selected");
        });
    });
    console.log("filled #attack-details");
    if (replaceState) {
        window.history.replaceState({href: href}, new_title, href);
    } else if(pushState) {
        window.history.pushState({href: href}, new_title, href);
    }

}

var loadFlowData = function(href) {
    console.log("got href: " + href);
    if (!href.match(/index\.php\?(.*)$/)){
        // something is wrong, we expect index.php urls 
        console.log("invalid URL, expecting index.php?...");
        return;
    }
    queryString  = RegExp.$1;
    // get needed vars from query string
    attack_id   = $.parseQuery(queryString).attack_id;
    target_ip   = $.parseQuery(queryString).target_ip;

    var url = "json/rpc/get_attack_flows.php";
    var params = {
        'attack_id': attack_id,
        'target_ip': target_ip,
    }
    $.getJSON(url, params, function(data) {
        $('#attack-flow-data').html(data.html); 
    });
}

var loadAttackGraph = function(e) {
    console.log("called loadAttackGraph");
    href = e.data('href');
    console.log("got href: " + href);
    if (!href.match(/index\.php\?(.*)$/)){
        // something is wrong, we expect index.php urls 
        console.log("invalid URL, expecting index.php?...");
        return;
    }
    queryString  = RegExp.$1;
    // get needed vars from query string
    attack_id      = $.parseQuery(queryString).attack_id;

    var url = "json/data/get_attack_graph.php";
    var params = {
        'attack_id': attack_id,
        'timezone_offset': (new Date()).getTimezoneOffset()
    }
    $.getJSON(url, params, function(data) {
        console.log("got attack graph, calling .plot");
        //$('#attack-profile-plot').plot([ data.plot_scan_data, data.plot_bruteforce_data, data.plot_compromise_data ]);
        $('#attack-profile-plot').plot([ data.data.scan, data.data.bruteforce, data.data.dieoff ]);
        console.log("post .plot()");
    });
}


var initialize_search = function() {
    console.log("initializing search page");

    // Set focus on input field
    $('input#search-ip').focus();

    $('#search-button').click(function(e){
        e.preventDefault();
        var url = "json/html/get_search_results.php";
        var params = {
            'ip':   $('#search-ip').val()
        }
        console.log("got params: " + params);
        $.getJSON(url, params, function(data) {
            $('#search-results-table').html(data.data);
            $('#search-results-container').show();
            attachHostDetailModals();
        });
    });
}

var initialize_status = function() {

    //$('#db-size-plot').setPlotLoading();
    //$('#target-count-plot').setPlotLoading();
    //$('#performance-plot').setPlotLoading();
    
    var backend_call_start = new Date(); // For measuring backend response time

    $.getJSON('json/data/get_backend_inittime.php', {}, function(data) {
        if (data == null) {
            // can not connect to backend, error
        } else {

            var response_time = new Date() - backend_call_start;
        
            init_time = new Date(data.backend_init_time * 1000);
            var formatted_init_time = init_time.toString();

            $('#status-info-table tr#backend-init-time td.value').text(formatted_init_time);
            $('#status-info-table tr#backend-init-time').show();
        
            $('#status-info-table tr#backend-response-time td.value').text(response_time + " ms");
            $('#status-info-table tr#backend-response-time').show();

            $.getJSON('json/data/get_backend_info.php', {}, function(data) {

                $('#status-info-table tr#backend-profile td.value').text(data.profile);
                $('#status-info-table tr#backend-profile').show();

                // -----
                sources = data.sources.replace(/:/g, ', ');
                
                $('#status-info-table tr#backend-sources td.value').text(sources);
                $('#status-info-table tr#backend-sources').show();
                // ------

                if (data.configs == '' || data.configs == null) {
                    $('#status-info-table tr#active-notification-configs td.value').html('<i>(none)</i>');
                } else {
                    $('#status-info-table tr#active-notification-configs td.value').text(data.configs);
                }
                
                $('#status-info-table tr#active-notification-configs').show();


                var db_size_min = data.db.db_size_min;
                var db_size_max = data.db.db_size_max;
                var time_min = data.db.time_min;
                var time_max = data.db.time_max;
                
                var plot_data = [{
                    label:  "Database size (MB)",
                    data:   data.db.data
                }];
                
                var graph_options = {
                    lines: {    show: true },
                    legend: { 	
                                container: $('#db-size-legend'),
                                noColumns: 1,
                                labelFormatter: function (label, series) {
                                    return "<span>" + label + '</span>';
                                }
                            },
                    grid: { 	hoverable: true, 
                                borderWidth: {top: 0, right: 0, left: 0, bottom:1},
                                clickable: true },
                    series: {   downsample: {
                                    threshold: 1000 }
                                },
                    xaxis: {    mode: 'time',
                                tickLength: 0,
                                timeformat: '%Y/%m/%d' },
                    yaxis: {    min: 0 }
                };
                
                var plot = $.plot($('#db-size-plot'), plot_data, graph_options);

                if (db_size_max > data.config.db_max_size) {
                    var db_max_size_data = {
                        data:       [ [ plot.getAxes().xaxis.min, data.config.db_max_size ], [ plot.getAxes().xaxis.max, data.config.db_max_size ] ],
                        color:      "#000",
                        dashes: {   show: true,
                                    lineWidth: 1 },
                        label:      "Maximum advized DB size",
                        lines: {    show: false },
                        points: {   show: false }
                    };
                
                    plot_data.push(db_max_size_data);
                
                    // Replot, including max DB size data
                    plot = $.plot($('#db-size-plot'), plot_data, graph_options);
                }
            });
        }
    });

        
    
    $.getJSON('json/data/get_status_info.php', {}, function(data) {
        var target_min = data.target.target_min;
        var target_max = data.target.target_max;
        var time_min = data.target.time_min;
        var time_max = data.target.time_max;
        
        var scan_data = {
            label:  "Scan",
            color:  "rgb(26, 150, 212)",
            data:   data.target.data.scan
        };
        var bruteforce_data = {
            label:  "Bruteforce",
            color:  "rgb(250, 100, 45)",
            data:   data.target.data.bruteforce
        };
        var compromise_data = {
            label:  "Compromise",
            color:  "rgb(220, 0, 8)",
            data:   data.target.data.compromise
        };
        
        var graph_options = {
            lines: {    show: true },
            legend: { 	
                        container: $('#target-count-legend'),
                        noColumns: 3,
                        labelFormatter: function (label, series) {
                            return "<span>" + label + '</span>';
                        },
                    },
			grid: { 	hoverable: true, 
                        borderWidth: {top: 0, right: 0, left: 0, bottom:1},
						clickable: true },
            series: {   downsample: {
                            threshold: 1000 }
                        },
            xaxis: {    mode: 'time',
                        tickLength: 0,
                        timeformat: '%Y/%m/%d' },
            yaxis: {    tickFormatter: function formatter(v, axis) {
                            if (v / 100000000 >= 1) return v.toString().substr(0, 3) + 'M';
                            else if (v / 10000000 >= 1) return v.toString().substr(0, 2) + 'M';
                            else if (v / 1000000 >= 1) return v.toString().substr(0, 1) + 'M';
                            else if (v / 100000 >= 1) return v.toString().substr(0, 3) + 'k';
                            else if (v / 10000 >= 1) return v.toString().substr(0, 2) + 'k';
                            else if (v / 1000 >= 1) return v.toString().substr(0, 1) + 'k';
                            else return v.toFixed(axis.tickDecimals);
                        },
                        min: 0 }
        };
        
        var plot = $.plot($('#target-count-plot'), [ scan_data, bruteforce_data, compromise_data ], graph_options);
    
        var flow_records_min = data.performance.flow_records_min;
        var flow_records_max = data.performance.flow_records_max;
        var time_min = data.performance.time_min;
        var time_max = data.performance.time_max;
        
        var flow_records_data = {
            label:  "Flow records",
            data:   data.performance.data.flow_records
        };
        var run_time_data = {
            label:  "Run time (s)",
            data:   data.performance.data.run_time,
            yaxis:  2
        };
        
        var graph_options = {
            lines: {    show: true },
            legend: { 	
                        container: $('#performance-legend'),
                        noColumns: 2,
                        labelFormatter: function (label, series) {
                            return "<span>" + label + '</span>';
                        },
                    },
			grid: { 	hoverable: true, 
                        borderWidth: {top: 0, right: 0, left: 0, bottom:1},
						clickable: true },
            series: {   downsample: {
                            threshold: 1000 }
                        },
            xaxis: {    mode: 'time',
                        tickLength: 0,
                        timeformat: '%Y/%m/%d' },
            yaxes: [    {   tickFormatter: function formatter(v, axis) {
                            if (v / 100000000 >= 1) return v.toString().substr(0, 3) + 'M';
                            else if (v / 10000000 >= 1) return v.toString().substr(0, 2) + 'M';
                            else if (v / 1000000 >= 1) return v.toString().substr(0, 1) + 'M';
                            else if (v / 100000 >= 1) return v.toString().substr(0, 3) + 'k';
                            else if (v / 10000 >= 1) return v.toString().substr(0, 2) + 'k';
                            else if (v / 1000 >= 1) return v.toString().substr(0, 1) + 'k';
                            else return v.toFixed(axis.tickDecimals);
                        },
                        min: 0 },
                        {   alignTicksWithAxis: 1,
                            position:   'right',
                            min: 0,
                            tickFormatter: function formatter(v, axis) {
                                return v.toFixed(0) + " s"
                            }} ]
        };
        
        var plot = $.plot($('#performance-plot'), [ flow_records_data, run_time_data ], graph_options);
    });
}

$(window).bind('popstate', function(event){
    if(event.originalEvent.state !== null) {
        console.log("originalEvent.state: " + event.originalEvent.state);
        loadPage(event.originalEvent.state.href, false);
    }
});

var attachHostDetailModals = function() {
    console.log("attachHostDetailModals called");
    $('a.ip-addr').click(function (e) {
        e.stopPropagation();
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

            $('#host-details div.modal-body a.ip-addr').click(function (e) {
                console.log("inception attach");
                e.stopPropagation();
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
            });

        // attach events on tr to go to actual attack pages
            $('#host-details table[id^=attacks-] tr').click(function () {
                loadPage($(this).data('href'));
                $('#host-details').modal('hide');
            });
        });
    });
}

$(document).ready(function() {
    console.log("document.ready from base.js");
    $('ul.nav-sidebar a').click(function(e){
        loadPage(e.target.href);
        e.preventDefault();
    });
});
