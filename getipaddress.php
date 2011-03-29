<?php

/**
 *  file       getipaddress.php
 * created on   mar 12, 2010
 * project      shawn_wilkerson
 * @package     MODxRevolutionBook
 * @subpackage Chapter06
 * @version     2.0
 * @category    network, server variables
 * @author    W. Shawn Wilkerson
 * @link    http://www.shawnwilkerson.com
 * @copyright  Copyright (c) 2009, W. Shawn Wilkerson.  All rights reserved.
 * @license
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 *
 ************************************************
 * purpose: discovers, tests, and returns ipv4 and/or ipv6 ip address
 *
 * requirements: a server running php > version 5.2
 *
 * parameters:
 *
 *  $mode (string)
 *          4       for ipv4
 *          6       for ipv6
 *          both    to test both ipv4 and ipv6 addresses
 *          default return all valid and invalid ip addresses
 *
 *  $showMethod (boolean) 1|0
 *          1           returns the method used to determine the ip address
 *          0 (default) hides the discovery method
 *
 */

if (!function_exists('test_ip4_address')) {

    /**
     * An array of server-side environment variables
     * @param array $addys     *
     * @return array The first valid ipv4 method and address sniffed from client browser.
     */
    function test_ip4_address($addys) {
        foreach ($addys as $key => $val) {
            if (filter_var(trim($val), FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE, FILTER_FLAG_NO_PRIV_RANGE, FILTER_FLAG_IPV4)) {
                $out = array(
                    $key => $val
                );
                break;
            }
        }
        return ($out) ? $out : false;
    }
}

if (!function_exists('test_ip6_address')) {

    /**
     * An array of server-side environment variables
     * @param array $addys
     * @return array The first valid method and ipv6 address sniffed from client browser.
     */
    function test_ip6_address($addys) {
        foreach ($addys as $key => $val) {
            if (filter_var(trim($val), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE, FILTER_FLAG_IPV6)) {
                $out = array(
                    $key => $val
                );
                break;
            }
        }
        return ($out) ? $out : false;
    }
}

/**
 * Detected IP Address
 * @var array
 */
$ip = '';

/**
 * Tested IPv4 IP Address
 * @var array
 */
$ipv4 = '';

/**
 * Tested IPv6 IP Address
 * @var array
 */
$ipv6 = '';

/**
 * Run-time Snippet Operation forced to lower case
 * @var string
 */
$mode = isset($mode) ? strtolower($mode) : 'both';

/**
 * Display the method utilized to get valid IP Address
 * @var boolean $showMethod
 */
$showMethod = isset($showMethod) ? $showMethod : false;

/**
 * Server sniffed browser ip addresses utilizing various method, some of
 * which will only work behind proxies or in other network / hardware situations
 * @var array
 */
$srvvals = array(
    'http_client_ip' => $_SERVER['HTTP_CLIENT_IP'],
    'http_x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'],
    'http_x_forwarded' => $_SERVER['HTTP_X_FORWARDED'],
    'http_x_cluster_client_ip' => $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'],
    'http_forwarded_for' => $_SERVER['HTTP_FORWARDED_FOR'],
    'http_forwarded' => $_SERVER['HTTP_FORWARDED'],
    'remote_addr' => $_SERVER['REMOTE_ADDR']
);

switch ($mode) {
    case '4' :
        $ip = test_ip4_address($srvvals);
        break;
    case '6' :
        $ip = test_ip6_address($srvvals);
        break;
    case 'both' :
        $ipv4 = test_ip4_address($srvvals);
        $ipv6 = test_ip6_address($srvvals);
        foreach ($ipv4 as $addy => $val) {
            $ip[$addy] = $val;
        }
        foreach ($ipv6 as $addy => $val) {
            $ip[$addy] = $val;
        }
        break;
    default :
        $ip = $srvvals;

}
foreach ($ip as $addy => $val) {
    /**
     * Check to see if we are being used as a MODx filter
     */
    $o .= ($showMethod) ? $addy . '=>' : '';
    $o .= $val . "\n";
}
return $o;



