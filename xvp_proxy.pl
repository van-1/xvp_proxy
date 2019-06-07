#!/usr/bin/env perl

# https://github.com/jberger/Mojo-Websockify
# http://xapi-project.github.io/xen-api/
# https://wiki.openstack.org/wiki/VNCConsoleCleanup
# https://tools.ietf.org/html/rfc6143

use Mojolicious::Lite;

#app->attr('novnc_url' => 'http://kanaka.github.io/noVNC/noVNC/vnc_auto.html');
#app->attr('novnc_url' => '/noVNC/vnc_lite.html');
app->attr('novnc_url' => '/noVNC/vnc.html');
app->attr('lastvm' => '');
app->static->paths->[0] = app->home->to_string.'/';

# Rewrite if behind proxy pass.
app->hook('before_dispatch' => sub {
    my $c = shift;
    app->attr('base' => '');
    if ($c->req->headers->header('X-Forwarded-For')) {
        my $base = $c->req->url->host;
        $c->req->url->base->path->parse($base);
        app->attr('base' => "/$base");
        $c->app->log->debug("Request under proxy pass, app->base = '".app->base()."'");
    }
});

helper api_call => sub {
  my $args;
  (my $c, my $cb, $args->{hostname}, $args->{method}, @{$args->{params}} ) = @_;
  $args->{params_string} .= '<param><value><string>'.$_.'</string></value></param>' foreach @{ $args->{params} };
  $c->ua->post(  $args->{hostname}
              => { Content_Type => 'text/xml' }
              => '<?xml version="1.0" encoding="us-ascii"?><methodCall><methodName>'.$args->{method}.'</methodName><params>'.$args->{params_string}.'</params></methodCall>'
              => sub { my ($ua, $tx) = @_;
                       $tx->{args} = $args;
                       $c->$cb($tx);
                     }
              );
};


# Ask the for a RFB console and get up the proxy
websocket '/*target' => sub {
  my $c = shift;
  $c->render_later;
  
  $c->on(finish => sub { warn 'websocket closing' });
  $c->tx->with_protocols('binary');
  my $tx = $c->tx;

  $c->delay(
    sub {
      
      my $server_ip = "";
      my $user = ""; 
      my $password = "";
      my $delay = shift;
      
      $c->app->log->info("[1] Authenticating to $server_ip");
      $c->api_call($delay->begin, $server_ip, 'session.login_with_password', $user, $password);
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        if ($res->error) {
          $c->app->log->error("Skipping '$res->{args}->{hostname}' due to ".$res->error->{message}."'");
          next;
        }
        my $token = $res->res->dom->find('member value')->last->text;
        $c->app->log->info("[2] Got token '$token from ".$res->original_remote_address);
        $delay->data->{$res->original_remote_address}->{token} =  $token;
        $c->api_call($delay->begin, $res->original_remote_address, 'VM.get_by_name_label', $token, $target );
      }
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $body = $res->res->body;
        my ($vmref) = $body =~ />(OpaqueRef:[^<]+)</;
        next unless $vmref;
        next if $delay->data->{found};
        $delay->data->{found}++;
        $c->app->log->info("[3] Found '$target' with vmref '$vmref' on ".$res->original_remote_address);
        my $token = $delay->data->{$res->original_remote_address}->{token};
        $c->api_call($delay->begin, $res->original_remote_address, 'VM.get_consoles', $token, $vmref );
      }
      # Return error if we got no results.
      $tx->finish(4500, "Got no results for $target") unless $delay->data->{found};
    },
    sub {
      my ($delay, @results) = @_;
      foreach my $res (@results) {
        my $token = $delay->data->{$res->original_remote_address}->{token};
        foreach my $conref ($res->res->dom->find('data value')->map('text')->each) {
          $c->app->log->info("[4] Got conref '$conref' on '$target'");
        $c->api_call($delay->begin, $res->original_remote_address, 'console.get_record', $token, $conref );
        }
      }
    },
    sub {
      my ($delay, @results) = @_;
      my $i = 1;
      foreach my $res (@results) {
        my $record;
       
        my $i = 0;
        for my $e ($res->res->dom->find('value')->first(qr/rfb/i)->find('value')->each) {
          if ($i == 2){
            $delay->data->{uuid} = $e->text;
          }
          my $is_rfb = index($e->text, 'rfb');
          if($is_rfb > -1){
              $record->{protocol} = 'rfb';
          }
          my $is_location = index($e->text, 'https');
          if($is_location > -1){
            $record->{location} = $e->text;
          }
          $i++;
        }
        
        $c->app->log->info("[5] Got the $record->{protocol} url $record->{location}");
        next unless $record->{protocol} eq 'rfb';
        $record->{token} = $delay->data->{$res->original_remote_address}->{token};
        ($record->{address}) = $record->{location} =~ m|://([^/]+)/|;
        $delay->pass($record);
      }
    },
    sub {
      my ($delay, @results) = @_;
      #print "cont steps = ".scalar(@results)."\n";
      foreach my $res (@results) {
      
        $res->{uuid} = $delay->data->{uuid};
        my $call = "CONNECT /console?uuid=$res->{uuid}&session_id=$res->{token} HTTP/1.0";
        
        $c->app->log->info("[6] Connect string is: '$call'");
        Mojo::IOLoop->client(address => $res->{address}, port => 80, sub {
          my ($loop, $err, $tcp) = @_;
          $tx->finish(4500, "TCP connection error: $err") if $err;

          $tcp->on(error => sub { $tx->finish(4500, "TCP error: $_[1]") });

          # This method will only trigger once so we can deal with the XVP response.
          $tcp->once(read => sub {
            my ($tcp, $bytes) = @_;
            my $length = length($bytes);
            my $not_standart_reply = 0;
            
            $c->app->log->info("[7] Auth response:\n$bytes $length bytes");
            print "raw bytes: |$bytes|\n";
            
            # Bail out unless we got a 200 status code.
            $tx->finish(4500, $bytes) if (index($bytes, '200') == -1);
            #Workaround for getting the ProtocolVersion Handshake with the response.
            #The standard reply is 78 bytes long, the Handshake is 12.
            $tx->send({binary => substr($bytes, -12)}) if $length == 90;
            $tx->send({text => "\r\n"}) if $length == 76;
            $not_standart_reply = 1 if $length == 76;
            
            $c->inactivity_timeout(300);
            $tcp->timeout(300);
           
            #Subscribe to the read event for the RFB stream.
            $tcp->on(read => sub {
              my ($tcp, $bytes) = @_;
              
              if($not_standart_reply == 1){
                $not_standart_reply = 0;
              } else {
                $tx->send({binary => $bytes});
              }
            });
            
           });
           
           $tx->on(binary => sub {
              my ($tx, $bytes) = @_;
              $tcp->write($bytes);
            });
           
           $tx->on(finish => sub {
              $tcp->close;
              undef $tcp;
              undef $tx;
           });

          # Perform the XVP auth call
          $tcp->write("$call\r\n\r\n");
        });
      }
    }
  );
};

# Base route
any '/' => sub {
  my $c = shift;
  my $host = $c->tx->local_address;
  my $port = $c->tx->local_port;
  my $novnc_url = app->novnc_url()."?autoconnect=true&host=$host&port=$port&path=";
  say app->lastvm();
  $c->render('index', novnc_url => $novnc_url);
};


app->secrets(['12345678']);
app->start;

__DATA__

@@ index.html.ep
<!DOCTYPE html>
<html>
<head>
  <title>noVNC Proxy</title>
  %= stylesheet 'https://cdnjs.cloudflare.com/ajax/libs/semantic-ui/2.2.4/semantic.min.css'
  <style type="text/css">
    #container { height: 100%; }
    #overlay {
      position: fixed;
      bottom: 5px;
      left: 5px;
      }
    #vnc {
      height: 100%;
      width: 100%;
      border: 0;
    }
  </style>
</head>
<body>
  <div id="container">
    <div id="overlay">
      <div class="ui mini right labeled input">
        <a id="fetch" class="ui black label">Fetch</a>
        <input id="choose" placeholder="Enter a Xen VM name..." type="text" autocomplete="off">
        <a id="connect" class="ui black tag label">Connect</a>
      </div>
    </div>
    <iframe id="vnc" src="<%= $novnc_url.app->lastvm() %>"></iframe>
  </div>
  %= javascript 'https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js'
  %= javascript begin
    %# Don't know if that's actually usefull
    $('#vnc').focus();
    %# Launch a noVNC popupto another host
    $('#connect').click(function(){
      window.open("<%== $novnc_url %>" + $('#choose').val());
      $('#choose').val('')
    });
    %# Enter on #choose will simulate a click on #connect
    $('#choose').keypress(function (e) {
      if (e.which == 13) {
        $('#connect').trigger('click');
        return false;
      }
    });
    %# Fetch and update the dom0s on backfground via websocket
    $('#fetch').click(function(){
      if (!("WebSocket" in window)) {
        alert('Your browser does not support WebSockets!');
      }
      var ws = new WebSocket("<%== url_for('fetch')->to_abs %>");
      ws.onopen = function () {
        ws.send(0);
      }
      ws.onmessage = function(e){
        var data = JSON.parse(e.data);
        alert(e.data);
      }
    });
  %= end
</body>
</html>

