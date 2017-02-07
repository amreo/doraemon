#!/usr/bin/perl -w

use esmith::Build::CreateLinks qw(:all);
use File::Basename;
use File::Path;


$event = "doraemon-reboot";
event_actions($event, 'doraemon-reboot' => 50);

$event = "doraemon-shutdown";
event_actions($event, 'doraemon-shutdown' => 50);

$event = "doraemon-wake";
event_actions($event, 'doraemon-wake' => 50);
