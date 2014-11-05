use Crypt::PBKDF2;

my $pbkdf2 = Crypt::PBKDF2->new(
    hash_class => 'HMACSHA1',
    iterations => 2000,
    output_len => 64,
    salt_len => 5,
);

$URL='http://www.participa2014.cat/onpucparticipar/data/';

while (<ARGV>) {
  chomp;
  if ($ARGV=~m{trams/(\d{5})\d*.dat}) {
    $muni= $1;
    $tram= (split /=/)[0];
  }
  else {
    $muni= $tram= $_;
  }
  $hash= $pbkdf2->PBKDF2_hex($muni, "k8BwrF-pZ9?r}v8".$tram);

  print $URL.substr($hash,0,1)."/".$hash.".h\n";
}
