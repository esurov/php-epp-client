<?php

namespace Metaregistrar\EPP;
/**
 * Created by PhpStorm.
 * User: thomasm
 * Date: 23.09.2015
 * Time: 13:51
 */
abstract class nicatEppConnection extends eppConnection
{
    /*
    |--------------------------------------------------------------------------
    | nicatEppConnection
    |--------------------------------------------------------------------------
    |
    | Is a general eppConnection parent class for all upcomming registry extensions
    | provided by Nic.at GmbH.
    |
    */

    private $doPeerVerification=true;

    /**
     * Wraps epp login, this function wrapper makes it easier to unittest the different
     * epp commands using mockery objects
     *
     * @return bool
     * @throws eppException
     */
    public function doLogin()
    {
        $login = new eppLoginRequest;
        if ((($response = $this->writeandread($login)) instanceof eppLoginResponse) && ($response->Success())) {
            $this->loggedin = true;
            return true;
        }
        return false;
    }

    /**
     * Disable Peer Verification for e.g. testing purposes
     *
     * @param bool|true $verifyPeer
     */
    public function setVerifyPeer($verifyPeer=true)
    {
        $this->doPeerVerification = $verifyPeer;
    }


    /**
     * Connect with DNS failover: resolve all IPs and try each one
     * @param string $hostname
     * @param int $port
     * @return boolean
     */
    public function connect($hostname = null, $port = null) {
        if ($hostname) {
            $this->hostname = $hostname;
        }
        if ($port) {
            $this->port = $port;
        }

        $ips = $this->resolveHostIps($this->hostname);
        if (empty($ips)) {
            // No IPs resolved — fall back to original hostname
            return $this->connectTo($this->hostname, $this->port);
        }

        foreach ($ips as $ip) {
            $target = $this->buildTargetWithIp($this->hostname, $ip, $this->port);
            $this->writeLog("Trying IP $ip for ".$this->getHostname(), "CONNECT");
            if ($this->connectTo($target, $this->port, $ip)) {
                return true;
            }
            $this->writeLog("Connection to $ip failed", "ERROR");
        }

        $this->writeLog("Connection could not be opened to any resolved IP for ".$this->getHostname(), "ERROR");
        return false;
    }

    /**
     * Connect to the address and port fsockopen replaces by general stream_socket_client
     * @param string $target Connection target (hostname:port or scheme://ip:port)
     * @param int $port
     * @param string|null $ip The resolved IP for logging, or null if connecting by hostname
     * @return boolean
     */
    protected function connectTo($target, $port, $ip = null) {
        if ($this->local_cert_path) {
            if ($ip !== null) {
                // Set peer_name so TLS verification uses the original hostname, not the IP
                if (!$this->sslContext) {
                    $this->sslContext = stream_context_create();
                }
                stream_context_set_option($this->sslContext, 'ssl', 'peer_name', $this->extractHost($this->hostname));
                // Build scheme://ip without port — parent::connect() appends :port itself
                $host = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$ip]" : $ip;
                if (($pos = strpos($this->hostname, '://')) !== false) {
                    $host = substr($this->hostname, 0, $pos + 3) . $host;
                }
                return parent::connect($host, $port);
            }
            return parent::connect(null, $port);
        }

        //We don't want our error handler to kick in at this point...
        putenv('SURPRESS_ERROR_HANDLER=1');
        $context = stream_context_create();
        if(!$this->doPeerVerification) {
            stream_context_set_option($context, 'ssl', 'verify_peer', false);
            stream_context_set_option($context, 'ssl', 'verify_peer_name', false);
        }

        if ($ip !== null) {
            stream_context_set_option($context, 'ssl', 'peer_name', $this->extractHost($this->hostname));
        } else {
            $target = $this->hostname . ":" . $this->port;
        }

        $errno = '';
        $errstr = '';
        $this->connection = @stream_socket_client($target, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);
        if (is_resource($this->connection)) {
            $this->writeLog("Connection made to ".($ip ?: $this->hostname),"CONNECT");
            stream_set_blocking($this->connection, false);
            stream_set_timeout($this->connection, $this->timeout);
            if ($errno == 0) {
                $this->connected = true;
                $this->read();
                putenv('SURPRESS_ERROR_HANDLER=0');
                return true;
            } else {
                putenv('SURPRESS_ERROR_HANDLER=0');
                return false;
            }
        }

        putenv('SURPRESS_ERROR_HANDLER=0');
        return false;
    }

    /**
     * Resolve all IP addresses for a hostname, stripping any scheme prefix.
     * @param string $hostname Hostname possibly prefixed with scheme (e.g. ssl://epp.example.com)
     * @return array List of IP addresses, or empty array if resolution fails
     */
    protected function resolveHostIps($hostname) {
        $host = $this->extractHost($hostname);
        // If the hostname is already an IP address, return it directly
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }
        $ips = [];
        // Resolve IPv4 (A) records
        $a = @dns_get_record($host, DNS_A);
        if (is_array($a)) {
            foreach ($a as $record) {
                $ips[] = $record['ip'];
            }
        }
        // Resolve IPv6 (AAAA) records
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $record) {
                $ips[] = $record['ipv6'];
            }
        }
        return $ips;
    }

    /**
     * Extract the bare hostname from a URI that may have a scheme prefix.
     * @param string $hostname e.g. "ssl://epp.example.com" or "tls://epp.example.com" or "epp.example.com"
     * @return string The bare hostname
     */
    protected function extractHost($hostname) {
        if (($pos = strpos($hostname, '://')) !== false) {
            return substr($hostname, $pos + 3);
        }
        return $hostname;
    }

    /**
     * Build a connection target string replacing the hostname with a resolved IP.
     * @param string $hostname Original hostname (possibly with scheme prefix)
     * @param string $ip Resolved IP address
     * @param int $port Port number
     * @return string Connection target (e.g. "ssl://192.0.2.1:700")
     */
    protected function buildTargetWithIp($hostname, $ip, $port) {
        // Wrap IPv6 addresses in brackets for URI notation
        $host = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[$ip]" : $ip;
        if (($pos = strpos($hostname, '://')) !== false) {
            $scheme = substr($hostname, 0, $pos + 3);
            return $scheme . $host . ':' . $port;
        }
        return $host . ':' . $port;
    }

}