#!/usr/bin/perl -w

package esmith;

use strict;
use Errno;
use esmith::DB::db;
use IO::File;
use English;
use JSON;

my $db_hosts = esmith::DB::db->open('hosts') || die("Could not open e-smith db (" . esmith::DB::db->error . ")\n");
my $db_configuration = esmith::DB::db->open('configuration') || die("Could not open e-smith db (" . esmith::DB::db->error . ")\n");

my @hostnames = ();
my %hostnames_map = ();
my %vars = ();

$vars{"proxy_status"} = $db_configuration->get_prop('squid', 'status');
$vars{"ansible_user"} = "amgmt";
$vars{"ansible_ssh_private_key_file"} = $db_configuration->get_prop('doraemon', 'ManagementPrivateKeyFile');

my $domainname = $db_configuration->get_prop('DomainName','type');

my @items = $db_hosts->get_all('local');
foreach my $item (@items) {
  $hostnames_map{$item} = $item->key . '.' . $domainname;
  push @hostnames, $item->key . '.' . $domainname;
}

my %output = ('clients' => {
  'hosts' => [ @hostnames ],
  'vars' => { %vars }
} );
my $json = encode_json \%output;
print "$json\n";

exit 0;
