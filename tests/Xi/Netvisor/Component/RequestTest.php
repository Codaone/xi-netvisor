<?php

namespace Xi\Netvisor\Component;

use GuzzleHttp\Psr7\Response;
use Xi\Netvisor\Component\Request;
use Xi\Netvisor\Config;
use GuzzleHttp\Client;

class RequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * Verify HMACSHA256 MAC calculation matches documented example
     */
    public function hmacsha256CalculationMatchesDocumentedExample()
    {
        // Values from Netvisor API documentation
        $url = 'https://isvapi.netvisor.fi/accounting.nv';
        $sender = 'ClientName';
        $customerId = 'Integration user identifier';
        $timestamp = '2023-05-04 12:00:00.000';
        $language = 'FI';
        $organisationId = '1967543-8';
        $transactionId = '123456';
        $timestampUnix = '1683147600';
        $customerKey = '7cd680e89e880553358bc07cd28b0ee2';
        $partnerKey = '7f94228d149a96b2f25e3edad55096e';

        $parameters = array(
            $url,
            $sender,
            $customerId,
            $timestamp,
            $language,
            $organisationId,
            $transactionId,
            $timestampUnix,
            $customerKey,
            $partnerKey,
        );

        $key = implode('&', array($customerKey, $partnerKey));
        $mac = hash_hmac('sha256', implode('&', $parameters), $key);

        // Expected value from Netvisor documentation
        $expectedMac = '86b8f6510744913deab32da404d7668eba2a75775b3ac78c9c48bca65e0fbd27';

        $this->assertEquals($expectedMac, $mac);
    }

    /**
     * @var Request
     */
    private $request;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $client;

    public function setUp()
    {
        parent::setUp();

        $this->client = $this->getMockBuilder('GuzzleHttp\Client')
            ->disableOriginalConstructor()
            ->getMock();

        $config = new Config(
            true,
            'http://integration.netvisor.fi',
            'sender',
            'customerId',
            'partnerId',
            'language',
            'organizationId',
            'userKey',
            'partnerKey'
        );

        $this->request = new Request($this->client, $config);
    }

    /**
     * @test
     */
    public function createsRequest()
    {
        $this->client->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'http://integration.netvisor.fi/accounting.nv',
                $this->anything()
            )
            ->will($this->returnValue(
                new Response('200', array(), 'hello')
            ));

        $this->request->post(
            '<?xml>',
            'accounting'
        );
    }

    /**
     * @test
     */
    public function throwsExceptionIfResponseStatusIsFailed()
    {
        $xmlResponse = <<<LUS
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Root>
    <ResponseStatus>
        <Status>FAILED</Status>
        <Status>AUTHENTICATION_FAILED :: Integraatiokumppania ei löydy, katso dokumentaatio</Status>
        <TimeStamp>7.4.2009 13:46:07</TimeStamp>
    </ResponseStatus>
</Root>
LUS;

        $this->client->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'http://integration.netvisor.fi/accounting.nv',
                $this->anything()
            )
            ->will($this->returnValue(
                new Response('200', array(), $xmlResponse)
            ));

        $this->setExpectedException(
            'Xi\Netvisor\Exception\NetvisorException',
            'AUTHENTICATION_FAILED :: Integraatiokumppania ei löydy, katso dokumentaatio'
        );

        $this->request->post(
            '<?xml>',
            'accounting'
        );
    }

    /**
     * @test
     */
    public function returnsResponseBodyIfResponseStatusIsOK()
    {
        $xmlResponse = <<<LUS
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Root>
    <ResponseStatus>
        <Status>OK</Status>
        <TimeStamp>7.4.2009 13:37:00</TimeStamp>
    </ResponseStatus>
</Root>
LUS;

        $this->client->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'http://integration.netvisor.fi/accounting.nv',
                $this->anything()
            )
            ->will($this->returnValue(
                new Response('200', array(), $xmlResponse)
            ));

        $response = $this->request->post(
            '<?xml>',
            'accounting'
        );

        $this->assertEquals($xmlResponse, $response);
    }
}
