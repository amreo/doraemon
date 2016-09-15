<?php
include_once("EsmithDatabase.php");
define('CONFIG_KEY', 'doraemon');

$hosts_db = new EsmithDatabase('hosts');
$roles_db = new EsmithDatabase('roles');
$config_db = new EsmithDatabase('configuration');

$uri = $_SERVER['REQUEST_URI'];
// add leading '/' to uri string, works if $uri is empty
$uri = (substr($uri, 0, 1) == '/') ? $uri : '/' . $uri;
$pos = strpos($uri, '?');
if (false !== $pos) {
    $route = substr($uri, 0, (int) $pos);
} else {
    $route = $uri;
}
// remove trailing '/'
$route = rtrim($route, '/');

$query_string = $_SERVER['QUERY_STRING'];
$get_params = array();
parse_str($query_string, $get_params);

// determine internal function name (all lowercase, dash2underscore, named ROUTE_routename )
$function = preg_replace(':\-:', '_', strtolower($route));
$function = preg_replace(':^/:', 'ROUTE_', $function);

if (function_exists($function)) {
    $function();
} else {
    die('Go away.');
}

function varsForRole($role, $json=true) {
    global $roles_db;
    $result = $roles_db->getKey($role);
    $return = array('role'=>$role,'delpkg'=>'','addpkg'=>'');
    if (is_array($result)) {
        if (is_string($result['Addpkg']))
            $return['addpkg'] = preg_split("/[\s,]+/", $result['Addpkg']);
        if (is_string($result['Delpkg']))
            $return['delpkg'] = preg_split("/[\s,]+/", $result['Delpkg']);
    }
    if ($json) {
        return json_encode($return);
    } else {
        return $return;
    }
}

function getClient($mac=false) {
    global $hosts_db;
    if (!$mac) {
        $mac = getClientMac();
        if (!$mac) return false;
    }
    $hosts = $hosts_db->getAllByProp('MacAddress',$mac);
    if (count($hosts)>0) {
        return array_pop($hosts);
    } else {
        return false;
    }
}

function getClientMac($ip=false) {
    if (false === $ip) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    $result = pingHost($ip,1);
    if (!$result) return false;
    $macAddr=false;
    $arptable=`arp -n $ip`;
    $lines=explode("\n", $arptable);
    foreach($lines as $line) {
       $cols=preg_split('/\s+/', trim($line));
       if ($cols[0]==$ip)
       {
           return $cols[2];
       }
    }
}

function newHostname($mac, $base, $role) {
    global $config_db;
    global $hosts_db;
    if(!preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac)) {
        echo "invalid mac address";
        return;
    }

    if ($client=getClient($mac)) {
        echo $client['name'];
        return;
    }

    $domainName = (string)$config_db->getKeyValue('DomainName');
    $digits = $config_db->getProp(CONFIG_KEY,'NamingDigits');
    $formatstring = '%s-%0'.$digits.'d';
    $nr=0;
    $hostname = '';
    do {
        $nr++;
        $hostname = sprintf($formatstring, $base, $nr);
#       TODO: we'll use the hostname in future, maybe
#        if (trim($domainName) != '') {
#            $hostname .= '.' . $domainName;
#        }
    } while ($hosts_db->getKey($hostname));

    $hosts_db->setKey($hostname, 'remote', array(
		'MacAddress'    => $mac,
		'Role'   		=> $role,
		'Description' 	=> ''
    ));

    echo $hostname;
}

function pingHost($host, $timeout=1) {
    $pingresult = exec("/bin/ping -c 1 -t 2 -W $timeout $host", $output, $retvar);
    return (0 == $retvar);
}



function ROUTE_domain() {
    global $config_db;
    $theFile = $config_db->getProp(CONFIG_KEY,'DomainFile');
    passthru("/usr/bin/sudo /bin/cat $theFile");
}

function ROUTE_mgmtkey() {
    global $config_db;
    $theFile = $config_db->getProp(CONFIG_KEY,'ManagementKeyFile');
    passthru("/usr/bin/sudo /bin/cat $theFile");
}

function ROUTE_epoptes_srv() {
    global $hosts_db;
    $hosts = $hosts_db->getAllByProp('Role','docenti');
    if (count($hosts) == 0) {
        echo 'none';
    } else {
        $host = array_pop($hosts);
        echo json_encode($host);
    }
}

function ROUTE_ansible_host() {
    global $get_params;
    if (isset($get_params['role'])) {
        $role = $get_params['role'];
    } elseif ($client = getClient()) {
        $role = $client['Role'];
    } else {
        $role = 'unknown';
    }
    echo varsForRole($role);
}

function ROUTE_hosts() {
    global $hosts_db;
    global $get_params;
    if (isset($get_params['role'])) {
        $items = $hosts_db->getAllByProp('Role', $get_params['role']);
    } else {
        $items = $hosts_db->getAll('remote');
    }
    $results=array();
    foreach ($items as $name=>$item) {
        $results[]=array(
            'mac'=>$item['MacAddress'],
            'hostname'=>$name,
            'role'=>$item['Role']
        );
    }
    echo json_encode($results);
}

function ROUTE_ansible_list() {
    global $get_params;
    if (isset($get_params['role'])) {
        $role = $get_params['role'];
    } elseif ($client = getClient()) {
        $role = $client['Role'];
    } else {
        $role = 'unknown';
    }
    $vars = varsForRole($role, false);
    echo json_encode(array(
        'localhost'=>array(
            'hosts'=>array('localhost'),
            'vars'=>array('ansible_connection'=>'local')
            ),
        '_meta'=> array('hostvars'=>array('localhost'=>$vars))
    ));
}

function ROUTE_vaultpass() {
    global $config_db;
    $theFile = $config_db->getProp(CONFIG_KEY,'VaultPassFile');
    $oArr = array();
    exec('/usr/bin/sudo /bin/cat ' . $theFile, $oArr, $exitCode);
    $content = trim(implode("\n", $oArr));
    if (false === $content) {
        echo 'no file'; return;
    }
    if (!$client = getClient()) {
        echo 'no client'; return;
    }
    $key = md5($client['name'], true);
    $padlenght = 16 - (strlen($content) % 16);
    $content_padded = $content . str_repeat('x', $padlenght);
    $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $content_padded, MCRYPT_MODE_ECB);
    echo base64_encode($ciphertext);
}

function ROUTE_whatsmyhostname() {
    global $config_db;
    $mac = getClientMac();
    if (!$mac) {
      echo 'no-mac-address';
      return false;
    }
    $base = $config_db->getProp(CONFIG_KEY,'NamingBase');
    $role = $config_db->getProp(CONFIG_KEY,'DefaultRole');
    newHostname($mac, $base, $role);
}

function ROUTE_mac2hostname() {
    global $config_db;
    global $get_params;
    $mac = getClientMac();
    if (!$mac) {
        echo 'Usage: GET /mac2hostname?mac=XX_XX_XX_XX_XX_XX[&base=YYY][&role=ZZZ]';
        return;
    }

    if (isset($get_params['role'])) {
        $role = $get_params['role'];
    } else {
        $role = $config_db->getProp(CONFIG_KEY,'DefaultRole');
    }

    if (isset($get_params['base'])) {
        $base = $get_params['base'];
    } else {
        $base = $config_db->getProp(CONFIG_KEY,'NamingBase');
    }

    newHostname($mac, $base, $role);
}
