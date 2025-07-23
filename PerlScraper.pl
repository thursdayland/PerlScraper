#!/usr/bin/env perl

use warnings;
use strict;
use feature 'say';
use LWP::UserAgent;
use IO::Socket::SSL;
use IO::Socket;
use Socket;
use Getopt::Std;
#install libgeo-ip-perl
#geoip-database-extra
use Geo::IP;
#install libtext-csv-perl
use Text::CSV;
#install libnet-dns-perl
use Net::DNS;

our($opt_u,$opt_n,$opt_r,$opt_c);
getopts('un:r:c:');
# options set
# $opt_u is a boolean for "unsafe mode" which can handle IP space that would not normally be desirable.
# $opt_n is a number of IPs to handle
sub HELP_MESSAGE {
	    say "A perl web scraper with some basic classification features";
	    say "Usage:";
	    say "PerlScraper.pl -u -n [number]";
	    say "-u        Unsafe mode. Grab IP space with no regard for where or what it is.";
	    say "-n        Limit the run to a certain number of random IPs. 0 for continuous run.";
		say "-r        Range mode. Specify a range of IPs either by CIDR or through range with a hyphen.";
		say "-c        Country mode. Specify a single country to crawl.";
	    say "";
	    die;
    }
sub VERSION_MESSAGE {
	    say "PerlScraper.pl -- version 0.0.20200308";
    }

$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

$ENV{HTTPS_DEBUG} = 1;

sub countryCheck {
	my ($ip) = @_;
	my $gi = Geo::IP->open("/usr/share/GeoIP/GeoIPCity.dat", GEOIP_STANDARD);
	my $record = $gi->record_by_addr($ip);
	if (!$record){
		return ("NULL");
	}
	return ($record->country_code);
}

sub rangeCheck {
	my ($ipRange) = @_;
	grep(/^[0-9]$/, $ipRange);

}

sub prepareIP{
	my ($u, $r, $c) = @_;
	#Subnets to disclude from any scans for technical reasons
	if ($r && $c) { print "The r and c options are incompatable.\n"};
	my %unusedIPSpace = (
		0x0a000000 => 0xff000000,
		0x00000000 => 0xff000000,
		0x7f000000 => 0xff000000,
		0xc0a80000 => 0xffff0000,
		0xac0c0000 => 0xfff00000,
		0x64400000 => 0xffc00000,
		0xc0586300 => 0xffffff00,
		0xc0000000 => 0xffffff00,
		0xc0000200 => 0xffffff00,
		0xc6336400 => 0xffffff00,
		0xcb007100 => 0xffffff00,
		0xe0000000 => 0xf0000000,
		0xf0000000 => 0xf0000000,
		0xc6120000 => 0xfffe0000,

	);
	# These are DoD subnets. Wouldn't recommend including them.
	my %sensitiveIPSpace = (
		0x06000000 => 0xff000000,
		0x07000000 => 0xff000000,
		0x0b000000 => 0xff000000,
		0x15000000 => 0xff000000,
		0x16000000 => 0xff000000,
		0x1a000000 => 0xff000000,
		0x1c000000 => 0xff000000,
		0x1d000000 => 0xff000000,
		0x1e000000 => 0xff000000,
		0x21000000 => 0xff000000,
		0x37000000 => 0xff000000,
		0xd6000000 => 0xff000000,
		0xd7000000 => 0xff000000,
	);

	# Make a random IP and check that it isn't in the invalid IP space described in the hash above.
	my $ip;
	my $checkIP = 1;
	if (!$u) {%unusedIPSpace = (%unusedIPSpace, %sensitiveIPSpace)};
	my $spaceCheck = 1;
	my $countryCheck = 0;

	while (!($spaceCheck && $countryCheck)){ 
		$spaceCheck = 1;
		$countryCheck = 0;
		$ip = int(rand(0xfffffffe));
		foreach my $privIP (keys %unusedIPSpace){
			my $mask = $unusedIPSpace{$privIP};
			my $scars = $mask & $ip;
			if (($mask & $ip) == $privIP) {
				#print STDERR "$ip is in invalid network $privIP\n";
				#$checkIP = 1;
				#last;
				$spaceCheck = 0;
			}
		}

		if ($c) {
			#	print intIPtoString($ip);
			#print "\n";
			#print countryCheck(intIPtoString($ip));
			#print "\n";
			if (countryCheck(intIPtoString($ip)) eq $c) {
				#	print countryCheck(intIPtoString($ip));
				#print "\n";
				$countryCheck = 1; 
				#print intIPtoString($ip);
				#print "\n";
			}
		}
		else {
			$countryCheck = 1;
		}
	}	

	return($ip);
}

sub intIPtoString {
	my ($ipInt) = @_;
	my $o1 =  "" . (($ipInt & 0xff000000) >> 24);
	my $o2 = "." . (($ipInt & 0x00ff0000) >> 16);
	my $o3 = "." . (($ipInt & 0x0000ff00) >> 8 );
	my $o4 = "." . (($ipInt & 0x000000ff) >> 0 );
	my $ipString = $o1 . $o2 . $o3 . $o4;
	return ($ipString);
}

sub validRange {
	my ($ipRange) = @_;
	if ($ipRange =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/) {
		if ( validIP($1) && ($2 < 33) ){
			print "Matches cidr.\n";
			return 1;
		}
	}
	elsif ($ipRange =~ m/^(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})-(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})$/){
		# Only check stringIPtoInt since validIP is builtin to that check
		if ( stringIPtoInt($2) > stringIPtoInt($1) ){
			print "Matches rage.\n";
			return 1;
		}
	}
	else {
		print STDERR "$ipRange is not a range in a supported format. Please see -h for supported formats.\n";
		return 2;
	}
}

sub validIP {
	# Check if an IP given as a string is a valid IP.
	# If it is, return 1. If not, return 0.
	my ($ipStr) = @_;
	if ($ipStr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/){
			if (($1 < 256) && ($2 < 256) && ($3 < 256) && ($4 < 256)){
				return 1;
			}
	}	
	print STDERR "$ipStr is not a valid IP address\n";
	return 0;
}

sub stringIPtoInt {
	my ($ipStr) = @_;
	if (validIP($ipStr) ne $ipStr){ return 2;}
	my $ipInt = 0;
	if ($ipStr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/){
		$ipInt = ($ipInt | ($1 << 24));
		$ipInt = ($ipInt | ($2 << 16));
		$ipInt = ($ipInt | ($3 <<  8));
		$ipInt = ($ipInt | ($4 <<  0));
		print $ipInt;
	}
	else {
		print STDERR "$ipStr could not be converted to an Int\n";
		$ipInt = 2;
	}
	
	return ($ipInt);
}

sub prepareBrowser{

	my $browser = LWP::UserAgent->new;
	my @headers = (
	'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
	'Accept' => '*/*',
	'Accept-Charset' => '*',
	'Accept-Language' => '*',
	);
	return($browser);
}
sub grabContent{
	my ($stringIP, $hostname) = @_;
	
	my $browser = LWP::UserAgent->new;
	my @headers = (
        'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',             'Accept' => '*/*',
	'Accept-Charset' => '*',
	'Accept-Language' => '*',
	);
	$browser->ssl_opts( 'verify_hostname' => 0, 'SSL_verify_mode' => 0x00);
	$browser->timeout(15);
	$browser->protocols_allowed( [ 'http', 'https', 'gopher' ]);
	my $response;
	my @success;

		my $sock80 = new IO::Socket::INET (PeerAddr => $stringIP,
									 PeerPort => 80,
									 Proto    => 'tcp',
									 Timeout  => 2);
		if ($sock80){
			if ($response = $browser->get("http://" . $stringIP,@headers)){
				open(OUT, ">./savedHTML/" . $stringIP . ".http") || die "savedHTML could not open\n";
				print OUT $response->content;
				close(OUT);
				@success[0] = 1;
			}
			if ($hostname){
				#$ip = $ptr->rdstring;
				if ($response = $browser->get("http://" . $hostname,@headers)){
					open(OUT, ">./savedHTML/" . $hostname . ".http") || die "savedHTML could not open\n";
					print OUT $response->content;
					close(OUT);
					@success[1] = 1;
				}
			}
		}
		my $sock443 = new IO::Socket::INET (PeerAddr => $stringIP,
									 PeerPort => 80,
									 Proto    => 'tcp',
									 Timeout  => 2);
		if ($sock443){
			if ($response = $browser->get("https://" . $stringIP,@headers)){
					open(OUT, ">./savedHTML/" . $stringIP . ".https") || die "savedHTML could not open\n";
					print OUT $response->content;
					close(OUT);
				@success[2] = 1;
			}
	
			if ($hostname){
				#$ip = $ptr->rdstring;
				if ($response = $browser->get("https://" . $hostname,@headers)){
					open(OUT, ">./savedHTML/" . $hostname . ".https") || die "savedHTML could not open\n";
					print OUT $response->content;
					close(OUT);
					@success[3] = 1;
				}
			}
		}
	return @success;
}

sub htmlToFile {



}

sub csvLogging {

	my $csv = Text::CSV->new () or
	die "".Text::CSV->error_diag ();

	my $aoa = csv (in => "file.csv");


}

sub main{
	if ($opt_n) {print "n is $opt_n \n";}
	
	#if ($opt_u) { print "u\n"};
	
	#f ($opt_r) { print "r is $opt_r \n"};
	
	
	my $ip = prepareIP($opt_u, $opt_r, $opt_c);
	
	
	my $stringIP = intIPtoString($ip);
	print $stringIP;
	print "\n";

	if ($opt_r) { validRange($opt_r);}

	my ($ptr) = rr($stringIP);
	my $hostname;
	if ($ptr) {
		$hostname = $ptr->rdstring; 
		$hostname =~ s/\.$//;
	}

	my @bww = grabContent($stringIP, $hostname);
	if (@bww){
		open(OUTCSV, ">>./results.csv") || die "results could not open\n";
		print OUTCSV $stringIP . "," . $hostname . "," .  countryCheck($stringIP) . "," . $bww[0] . "," . $bww[1] . "," . $bww[2] . "," . $bww[3];
		print OUTCSV "\n";
	}
}
main();
