var statusimg = "../static/images/online.png"

$(document).ready(function(e) {

    getOnlineUsers();
    getCurrentMessages();
    getPrivateMessages();
    switchSendingButton();
    Loop();

    $("#send-broadcast").click(function(e) {
        console.log('button pressed')
        $.post("/sendbroadcast", {"message": $("input").val()})

            .done(function(string) {
                console.log(string)
            });

            e.preventDefault();
    });

    $("#send-private-message").click(function(e) {
        console.log('button pressed')
        $.post("/send_private_message", {"message": $("#prmsg").val(), "username": $("#pruser").val()})

            .done(function(string) {
                console.log(string)
            });

            e.preventDefault();
    });

    $("#online-button").click(function(e) {
        console.log('button pressed')
        $.post("/changestatus", {"status": "online"})

            .done(function(string) {
                console.log(string)
                document.getElementById("status") = "online";
            });

            e.preventDefault();
    });

    $("#away-button").click(function(e) {
        console.log('button pressed')
        $.post("/changestatus", {"status": "away"})

            .done(function(string) {
                console.log(string)
                document.getElementById("status") = "away";
            });

            e.preventDefault();
    });

    $("#busy-button").click(function(e) {
        console.log('button pressed')
        $.post("/changestatus", {"status": "busy"})

            .done(function(string) {
                console.log(string)
                document.getElementById("status") = "busy";
            });

            e.preventDefault();
    });

    $("#offline-button").click(function(e) {
        console.log('button pressed')
        $.post("/changestatus", {"status": "offline"})

            .done(function(string) {
                console.log(string)
                document.getElementById("status") = "offline";
            });

            e.preventDefault();
    });

    setTimeout(getOnlineUsers, 5000);
    setTimeout(getCurrentMessages, 5000);
    setTimeout(getPrivateMessages, 5000);
    setTimeout(Loop, 240000);

});

function getOnlineUsers() {
    $.ajax({
        url: '/get_online_users',
        type: 'get',
        success: function(data) {
            let jsondata = JSON.parse(data)
            let users = jsondata['users'];
            let item = document.getElementById('user-list')
            item.innerHTML = '';

            for(var i = 0; i < users.length; i++) {

                newelement = document.createElement('li');
                newelement.className = 'list-group-item text-center';
                text = document.createTextNode(users[i]['username'] + " - " + users[i]['status']);

                newelement.appendChild(text)

                item.appendChild(newelement)

            }

        },
        complete:function(data){
            setTimeout(getOnlineUsers, 5000);
        }
    });
}


function getCurrentMessages() {
    $.ajax({
        url: '/get_current_messages',
        type: 'get',
        success: function(data) {
            let jsondata = JSON.parse(data)

            let msgs = jsondata['messagelist'];
            let item = document.getElementById('msg-list')


            item.innerHTML = '';

            for(var i = 0; i < msgs.length; i++) {

                newelement = document.createElement('li');
                newelement.className = 'list-group-item text-center';

                text = document.createTextNode(msgs[i]['username'] + " - " + msgs[i]['message']);
                newelement.appendChild(text);

                item.appendChild(newelement);

            }

        },
        complete:function(data){
            setTimeout(getCurrentMessages, 5000);
        }
    });
}

function getPrivateMessages() {
    $.ajax({
        url: '/get_private_messages',
        type: 'get',
        success: function(data) {
            let jsondata = JSON.parse(data)

            console.log(jsondata);

            let msgs = jsondata['messagelist'];
            let item = document.getElementById('pr-msg-list')

            console.log(item);

            item.innerHTML = '';

            for(var i = 0; i < msgs.length; i++) {

                newelement = document.createElement('li');
                newelement.className = 'list-group-item text-center';

                text = document.createTextNode(msgs[i]['username'] + " - " + msgs[i]['message']);
                newelement.appendChild(text);

                item.appendChild(newelement);
                console.log(msgs[i]['message']);

            }

        },
        complete:function(data){
            setTimeout(getPrivateMessages, 5000);
        }
    });
}

function Loop() {
    $.ajax({
        url: '/loopy',
        type: 'post',
        success: function(data) {
            console.log(data);
        },
        complete:function(data){
            setTimeout(Loop, 240000);
        }
    });
}


function switchSendingButton() {

    document.getElementById("switch-button").click(function(e){

        console.log("button has been pressed");

    });

}
