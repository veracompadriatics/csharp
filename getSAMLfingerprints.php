<?php
/*
Fetches SAML federation metadata url and extracts signing certificate fingerprints into a config file.
Useful for automating key rollover in a SAML integrated application.
*/
$metadata_url='https://login.microsoftonline.com/<tenand id>/FederationMetadata/2007-06/FederationMetadata.xml';
$output_configfile='config.ini';

/////////////////////////
$m =file_get_contents($metadata_url);
$x = xml_parser_create();
$d = array();
$i = array();
if(xml_parse_into_struct($x,$m,$d,$i))
  {
  preg_match('@^(?:https?://)?([^/]+)@i',$metadata_url,$idp_name);
  $idp_data = array('idp_name' => $idp_name[1]);
  if(array_key_exists('ENTITYDESCRIPTOR',$i))
    {
    $idp_data['idp_identifier'] = $d[$i['ENTITYDESCRIPTOR'][0]]['attributes']['ENTITYID'];
    }
  elseif( array_key_exists('MD:ENTITYDESCRIPTOR',$i) )
    {
    $idp_data['idp_identifier'] = $d[$i['MD:ENTITYDESCRIPTOR'][0]]['attributes']['ENTITYID'];
    }
  else
    {
    $idp_data['idp_identifier'] = '';
    }
  if( array_key_exists('SINGLESIGNONSERVICE',$i) )
    {
    $idp_data['idp_signon'] = $d[$i['SINGLESIGNONSERVICE'][0]]['attributes']['LOCATION'];
    }
  elseif( array_key_exists('MD:SINGLESIGNONSERVICE',$i) )
    {
    $idp_data['idp_signon'] = $d[$i['MD:SINGLESIGNONSERVICE'][0]]['attributes']['LOCATION'];
    }
  else
    {
    $idp_data['idp_signon'] = '';
    }
	
  if( array_key_exists('SINGLELOGOUTSERVICE',$i) )
  {
	$idp_data['idp_logout'] = $d[$i['SINGLELOGOUTSERVICE'][0]]['attributes']['LOCATION'];
  }
  elseif( array_key_exists('MD:SINGLELOGOUTSERVICE',$i) )
  {
	$idp_data['idp_logout'] = $d[$i['MD:SINGLELOGOUTSERVICE'][0]]['attributes']['LOCATION'];
  }
  else
  {
	$idp_data['idp_logout'] = '';
  }
  
  if ( array_key_exists('DS:X509CERTIFICATE',$i) )
  {
	$idp_data['idp_fingerprints']=array();
	for($n=0; $n<sizeof($i['DS:X509CERTIFICATE']); $n++)
	{
		array_push($idp_data['idp_fingerprints'], sha1( base64_decode($d[$i['DS:X509CERTIFICATE'][$n]]['value'])));
	}
  }
  elseif ( array_key_exists('X509CERTIFICATE',$i) )
  {
	$idp_data['idp_fingerprints']=array();
	for($n=0; $n<sizeof($i['X509CERTIFICATE']); $n++)
	{
		array_push($idp_data['idp_fingerprints'], sha1( base64_decode($d[$i['X509CERTIFICATE'][$n]]['value'])));
	}
  }
  else
  {
	$idp_data['idp_fingerprints'] = array_push($idp_data['idp_fingerprints'],'0000000000000000000000000000000000000000');
  }
  $idp_data['idp_fingerprints']=array_unique($idp_data['idp_fingerprints']);
  
  $contents =  '[' . $idp_data['idp_identifier'] . ']'."\n";
  $contents .= '  name = "' . $idp_data['idp_name'] . '"'."\n";
  $contents .= '  SingleSignOnService = "' . $idp_data['idp_signon'] . '"'."\n";
  $contents .= '  SingleLogoutService = "' . $idp_data['idp_logout'] . '"'."\n";
  foreach($idp_data['idp_fingerprints'] as $fingerprint)
    $contents .= '  certFingerprint[] = "' . str_replace(':','',$fingerprint) . '"'."\n";
  file_put_contents( $output_configfile, $contents );
  }  

?>
