<?php
require_once(dirname(__FILE__).'/../vendor/autoload.php');
require_once(dirname(__FILE__).'/../autoloader.php');

use PHPUnit\Framework\TestCase;
use Metaregistrar\EPP\nicatEppConnection;

/**
 * Concrete subclass to make the abstract nicatEppConnection testable.
 * Overrides connectTo() to avoid real network connections.
 */
class TestableNicatEppConnection extends nicatEppConnection
{
    /** @var array IPs that connectTo() should fail on */
    public $failingIps = [];

    /** @var array log of connectTo() calls: [target, port, ip] */
    public $connectToCalls = [];

    /** @var array|null Override DNS resolution results. Null = use real DNS. */
    public $mockResolvedIps = null;

    public function __construct()
    {
        // Skip parent constructor to avoid needing config files
    }

    protected function connectTo($target, $port, $ip = null)
    {
        $this->connectToCalls[] = ['target' => $target, 'port' => $port, 'ip' => $ip];

        // Simulate failure for specified IPs
        if ($ip !== null && in_array($ip, $this->failingIps)) {
            return false;
        }

        $this->connected = true;
        return true;
    }

    protected function resolveHostIps($hostname)
    {
        if ($this->mockResolvedIps !== null) {
            return $this->mockResolvedIps;
        }
        return parent::resolveHostIps($hostname);
    }

    // Expose protected methods for testing
    public function testExtractHost($hostname)
    {
        return $this->extractHost($hostname);
    }

    public function testBuildTargetWithIp($hostname, $ip, $port)
    {
        return $this->buildTargetWithIp($hostname, $ip, $port);
    }

    public function testResolveHostIps($hostname)
    {
        return parent::resolveHostIps($hostname);
    }

    public function writeLog($text, $action)
    {
        // Suppress logging during tests
    }
}

class nicatEppConnectionDnsFailoverTest extends TestCase
{
    // -------------------------------------------------------
    // extractHost tests
    // -------------------------------------------------------

    public function testExtractHostWithSslScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame('epp.example.com', $conn->testExtractHost('ssl://epp.example.com'));
    }

    public function testExtractHostWithTlsScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame('epp.example.com', $conn->testExtractHost('tls://epp.example.com'));
    }

    public function testExtractHostWithoutScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame('epp.example.com', $conn->testExtractHost('epp.example.com'));
    }

    // -------------------------------------------------------
    // buildTargetWithIp tests
    // -------------------------------------------------------

    public function testBuildTargetWithIpv4AndScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(
            'ssl://192.0.2.1:700',
            $conn->testBuildTargetWithIp('ssl://epp.example.com', '192.0.2.1', 700)
        );
    }

    public function testBuildTargetWithIpv4NoScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(
            '192.0.2.1:700',
            $conn->testBuildTargetWithIp('epp.example.com', '192.0.2.1', 700)
        );
    }

    public function testBuildTargetWithIpv6AndScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(
            'ssl://[2001:db8::1]:700',
            $conn->testBuildTargetWithIp('ssl://epp.example.com', '2001:db8::1', 700)
        );
    }

    public function testBuildTargetWithIpv6NoScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(
            '[2001:db8::1]:700',
            $conn->testBuildTargetWithIp('epp.example.com', '2001:db8::1', 700)
        );
    }

    public function testBuildTargetWithTlsScheme()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(
            'tls://10.0.0.1:443',
            $conn->testBuildTargetWithIp('tls://epp.example.com', '10.0.0.1', 443)
        );
    }

    // -------------------------------------------------------
    // resolveHostIps tests
    // -------------------------------------------------------

    public function testResolveHostIpsWithIpv4Literal()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(['192.0.2.1'], $conn->testResolveHostIps('192.0.2.1'));
    }

    public function testResolveHostIpsWithIpv6Literal()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(['2001:db8::1'], $conn->testResolveHostIps('2001:db8::1'));
    }

    public function testResolveHostIpsWithSchemePrefix()
    {
        $conn = new TestableNicatEppConnection();
        $this->assertSame(['10.0.0.1'], $conn->testResolveHostIps('ssl://10.0.0.1'));
    }

    public function testResolveHostIpsWithUnresolvableHost()
    {
        $conn = new TestableNicatEppConnection();
        $result = $conn->testResolveHostIps('this.host.does.not.exist.invalid');
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    // -------------------------------------------------------
    // connect failover logic tests
    // -------------------------------------------------------

    public function testConnectTriesAllIpsAndSucceedsOnSecond()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['192.0.2.1', '192.0.2.2'];
        $conn->failingIps = ['192.0.2.1']; // first IP fails

        $result = $conn->connect();

        $this->assertTrue($result);
        $this->assertCount(2, $conn->connectToCalls);
        $this->assertSame('192.0.2.1', $conn->connectToCalls[0]['ip']);
        $this->assertSame('192.0.2.2', $conn->connectToCalls[1]['ip']);
    }

    public function testConnectSucceedsOnFirstIp()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['192.0.2.1', '192.0.2.2'];

        $result = $conn->connect();

        $this->assertTrue($result);
        $this->assertCount(1, $conn->connectToCalls);
        $this->assertSame('192.0.2.1', $conn->connectToCalls[0]['ip']);
    }

    public function testConnectFailsWhenAllIpsFail()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['192.0.2.1', '192.0.2.2'];
        $conn->failingIps = ['192.0.2.1', '192.0.2.2'];

        $result = $conn->connect();

        $this->assertFalse($result);
        $this->assertCount(2, $conn->connectToCalls);
    }

    public function testConnectFallsBackToHostnameWhenNoIpsResolved()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = []; // DNS resolution fails

        $result = $conn->connect();

        $this->assertTrue($result);
        $this->assertCount(1, $conn->connectToCalls);
        $this->assertNull($conn->connectToCalls[0]['ip']);
        $this->assertSame('ssl://epp.example.com', $conn->connectToCalls[0]['target']);
    }

    public function testConnectWithIpv6Failover()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['192.0.2.1', '2001:db8::1'];
        $conn->failingIps = ['192.0.2.1']; // IPv4 fails, IPv6 succeeds

        $result = $conn->connect();

        $this->assertTrue($result);
        $this->assertCount(2, $conn->connectToCalls);
        $this->assertSame('ssl://[2001:db8::1]:700', $conn->connectToCalls[1]['target']);
        $this->assertSame('2001:db8::1', $conn->connectToCalls[1]['ip']);
    }

    public function testConnectPassesCorrectTargetFormat()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://epp.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['10.0.0.1'];

        $conn->connect();

        $this->assertSame('ssl://10.0.0.1:700', $conn->connectToCalls[0]['target']);
        $this->assertSame(700, $conn->connectToCalls[0]['port']);
    }

    public function testConnectSetsHostnameAndPort()
    {
        $conn = new TestableNicatEppConnection();
        $conn->setHostname('ssl://old.example.com');
        $conn->setPort(700);
        $conn->mockResolvedIps = ['10.0.0.1'];

        $conn->connect('ssl://new.example.com', 800);

        $this->assertSame('ssl://new.example.com', $conn->getHostname());
        $this->assertSame(800, $conn->getPort());
    }
}
