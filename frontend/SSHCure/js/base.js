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

    // TODO: when we get the more complex links (filter_range etc)
    // we should only save those query params that matter for comparison
    if (replaceState) {
        window.history.replaceState({href: href}, new_title, href);
    } else if(pushState) {
        window.history.pushState({href: href}, new_title, href);
    }

    $('div#main').load("index.php?action=" + action + "&block=main", function() {
        // This switch functions as a $(document).ready for asynchronous page loads
        switch (action) {
            case "dashboard":
                if (typeof d !== 'object') {
                    var d = new Dashboard();
                    d.initialize();
                }
                break;
        }
    });
}

$(window).bind('popstate', function(event){
        console.log(event.originalEvent.state);
        loadPage(event.originalEvent.state.href, false);
});

$(document).ready(function() {
    console.log("document.ready from base.js");
    $('ul.nav-sidebar a').click(function(e){
        loadPage(e.target.href);
        e.preventDefault();
    });
});
