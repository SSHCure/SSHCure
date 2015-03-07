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
                //plot_incoming_attacks_plot(d.internal_networks);
                break;
            case "search":
                console.log("loaded search page");
                initialize_search();
                break;
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
        });


    });
}

$(window).bind('popstate', function(event){
    if(event.originalEvent.state !== null) {
        console.log("originalEvent.state: " + event.originalEvent.state);
        loadPage(event.originalEvent.state.href, false);
    }
});

$(document).ready(function() {
    console.log("document.ready from base.js");
    $('ul.nav-sidebar a').click(function(e){
        loadPage(e.target.href);
        e.preventDefault();
    });
});
