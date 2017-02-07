<?php

/*
 * Copyright (C) 2011 Nethesis S.r.l.
 * 
 * This script is part of NethServer.
 * 
 * NethServer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * NethServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NethServer.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Read and write parameters into SME DB
 *
 * Ths class implements an interface to SME database executing the command /sbin/e-smith/db with sudo.
 * The class needs /etc/sudoers configurazione. In the sudoers file you must have something like this:
 * <code>
 * Cmnd_Alias SME = /sbin/e-smith/db, /sbin/e-smith/signal-event
 * www ALL=NOPASSWD: SME
 * </code>
 *
 *
 * @author Giacomo Sanchietti <giacomo.sanchietti@nethesis.it>
 * @author Davide Principi <davide.principi@nethesis.it>
 * @since 1.0
 * @internal
 */
class EsmithDatabase
{

    /**
     * @var SME DB database command
     * */
    private $command = "/usr/bin/sudo /sbin/e-smith/db";

    /**
     * @var $db Database name, it's translated into the db file path. For example: /home/e-smith/db/testdb
     * */
    private $db;

    /**
     * This static class variable shares a socket connection to smwingsd
     *
     * @var resource
     */
    private static $socket;




    /**
     * Construct an object to access a SME Configuration database file
     * with $user's privileges.
     * 
     * @param string $database Database name
     */
    public function __construct($database)
    {
        if ( ! $database)
            sprintf("%s: You must provide a valid database name.", get_class($this));

        $this->db = $database;
    }

    public function getAll($type = NULL)
    {
        $output = "";

        $ret = $this->dbRead('getjson', array(), $output);
        if ($ret !== 0) {
            sprintf("%s: internal database command failed!", __CLASS__);
        }

        $data = json_decode($output, TRUE);
        if ( ! is_array($data)) {
            sprintf("%s: unexpected json string `%s`", __CLASS__, substr($output, 0, 8));
        }

        $result = array();

        foreach ($data as $item) {
            // Apply type check filter:
            if (isset($type) && $type !== $item['type']) {
                continue;
            }
            $props = isset($item['props']) ? $item['props'] : array();
            $result[$item['name']] = array_merge($props, array('type' => $item['type']));
        }

        return $result;
    }

    public function getAllByProp($propName = NULL, $propValue = NULL)
    {
        $output = "";

        $ret = $this->dbRead('getjson', array(), $output);
        if ($ret !== 0) {
            sprintf("%s: internal database command failed!", __CLASS__);
        }

        $data = json_decode($output, TRUE);
        if ( ! is_array($data)) {
            sprintf("%s: unexpected json string `%s`", __CLASS__, substr($output, 0, 8));
        }

        $result = array();

        foreach ($data as $item) {
            $item['props']['type'] = $item['type'];
            $item['props']['name'] = $item['name'];
            
            if (isset($propName) && isset($propValue)) {
                if (isset($item['props'][$propName]) && $propValue == $item['props'][$propName]) {
                    $result[$item['name']] = $item['props'];  
                }
            } else {
                $result[$item['name']] = $item['props'];  
            }
        }

        return $result;
    }
    
    public function getKey($key)
    {
        $output = '';

        $ret = $this->dbRead('getjson', array($key), $output);
        if ($ret !== 0) {
            sprintf("%s: internal database command failed", __CLASS__);
        }

        $data = json_decode($output, TRUE);

        if ($data === 1) {
            // Key has not been found
            return array();
        } elseif ( ! is_array($data)) {
            sprintf("%s: unexpected json string `%s`", __CLASS__, substr($output, 0, 8));
        } 
        
        $data['props']['type'] = $data['type'];
        $data['props']['name'] = $data['name'];
        return $data['props'];
    }
    
    public function getKeyValue($key)
    {
        $output = '';

        $ret = $this->dbRead('getjson', array($key), $output);
        if ($ret !== 0) {
            sprintf("%s: internal database command failed", __CLASS__);
        }

        $data = json_decode($output, TRUE);

        if ($data === 1) {
            // Key has not been found
            return array();
        } elseif ( ! is_array($data)) {
            sprintf("%s: unexpected json string `%s`", __CLASS__, substr($output, 0, 8));
        } 
        
        return $data['type'];
    }

    public function setKey($key, $type, $props)
    {
        $output = NULL;
        $ret = $this->dbExec('set', $this->prepareArguments($key, $type, $props), $output);
        return ($ret == 0);
    }

    public function deleteKey($key)
    {
        $output = NULL;
        $output = NULL;
        $ret = $this->dbExec('delete', $this->prepareArguments($key), $output);
        return ($ret == 0);
    }

    /**
     * Return the type of a key
     * Act like: /sbin/e-smith/db dbfile gettype key
     * 
     * @param string $key the key to retrieve
     * @access public
     * @return string the type of the key
     */
    public function getType($key)
    {
        $output = NULL;
        $ret = $this->dbRead('gettype', array($key), $output);
        return trim($output);
    }

    /**
     * Set the type of a key 
     * Act like: /sbin/e-smith/db dbfile settype key type
     * 
     * @param string $key the key to change
     * @param string $type the new type
     * @access public
     * @return bool true on success, FALSE otherwise
     */
    public function setType($key, $type)
    {
        $output = NULL;
        $ret = $this->dbExec('settype', $this->prepareArguments($key, $type), $output);
        return ($ret == 0);
    }

    public function getProp($key, $prop)
    {
        $output = NULL;
        $ret = $this->dbRead('getprop', array($key, $prop), $output);
        return trim($output);
    }

    public function setProp($key, $props)
    {
        $output = NULL;
        $ret = $this->dbExec('setprop', $this->prepareArguments($key, $props), $output);
        return ($ret == 0);
    }

    public function delProp($key, $props)
    {
        $output = NULL;
        $ret = $this->dbExec('delprop', array_merge(array($key), array_values($props)), $output);
        return ($ret == 0);
    }

    /**
     * Execute the db command
     * @param string $command The command to invoke
     * @param array $args The command arguments
     * @param string &$output The output from the command process
     * @return int  The command exit code
     */
    private function dbExec($command, $args, &$output)
    {
        // prepend the database name and command
        array_unshift($args, $this->db, $command);
        $exitCode = 0;
        $oArr = array();
        exec($this->command . ' ' . implode(' ', array_map('escapeshellarg', $args)), $oArr, $exitCode);
        $output = implode("\n", $oArr);
        return $exitCode;
    }

    /**
     * Read db data from memory cache daemon
     * @param string $command The command to invoke
     * @param array $args The command arguments
     * @param string &$output The output from the read socket
     * @return int  The command exit code
     */
    private function dbRead($command, $args, &$output)
    {
        if ( ! isset(self::$socket) ) {
            $socketPath = '/var/run/smwingsd.sock';
            $errno = 0;
            $errstr = '';
            self::$socket = fsockopen('unix://' . $socketPath, -1, $errno, $errstr);
            if( ! is_resource(self::$socket)) {
                sprintf("Invalid socket (%d): %s. Fall back to exec().", $errno, $errstr);
            }
        }
         
        if ( ! is_resource(self::$socket)) {
            return $this->dbExec($command, call_user_func_array(array($this, 'prepareArguments'), $args), $output);            
        }

        // prepend the database name and command
        array_unshift($args, $this->db, $command);

        $ret =  $this->sendMessage(self::$socket, 0x10, $args);
        if ( ! $ret ) {
            return 1;
        }
        $ret = $this->recvMessage(self::$socket);
        if ( ! $ret ) {
            return 1;
        }
        if ($command === 'getjson') {
            $output = $ret;
        } else {
            $output = json_decode($ret, TRUE);
        }
        
        return 0;
    }

    private function sendMessage($socket, $type, $args = array())
    {
        $payload = json_encode($args);
        $data = pack('CN', (int) $type, strlen($payload)) . $payload;
        $written = fwrite($socket, $data);
        if ($written !== strlen($data)) {
            echo 'Socket write error';
        }
        return TRUE;
    }

    private function recvMessage($socket)
    {
        $buf = $this->safeRead($socket, 5);
        if ($buf === FALSE) {
            echo 'Socket read error';
            return false;
        }

        $header = unpack('Ctype/Nsize', $buf);
        if ( ! is_array($header)) {
            echo 'Invalid message header';
            return false;
        }

        $message = $this->safeRead($socket, $header['size']);
        if ($message === FALSE) {
            echo 'Socket read error';
            return false;
        }

        if ($header['type'] & 0x02) {
            return NULL;
        }

        return $message;
    }

    private function safeRead($socket, $size) 
    {
        $buffer = "";
        $count = 0;
        while($count < $size) {
            if(feof($socket)) {
                return FALSE;
            }
            $chunk = fread($socket, $size - $count);
            $count += strlen($chunk);
            if($chunk === FALSE) {
                return FALSE;
            }
            $buffer .= $chunk;
        }
        return $buffer;
    }


    /**
     * Take arbitrary arguments and flattenize to an array
     *
     * @param mixed $_
     * @return array
     */
    private function prepareArguments()
    {
        $args = array();

        foreach (func_get_args() as $arg) {
            if (is_array($arg)) {
                foreach ($arg as $propName => $propValue) {
                    $args[] = $propName;
                    $args[] = $propValue;
                }
            } else {
                $args[] = (String) $arg;
            }
        }

        return $args;
    }




}