<?php
namespace Xi\Netvisor;

use Guzzle\Http\Client;
use JMS\Serializer\Naming\IdenticalPropertyNamingStrategy;
use JMS\Serializer\SerializerBuilder;
use Xi\Netvisor\Config;
use Xi\Netvisor\Component\Request;
use Xi\Netvisor\Exception\NetvisorException;
use Xi\Netvisor\Component\Validate;
use Xi\Netvisor\Resource\Xml\Component\Root;
use JMS\Serializer\Serializer;

/**
 * Connects to Netvisor-interface via HTTP.
 * Authentication is based on HTTP headers.
 * A single XML file is sent to the server.
 * The server returns a XML response that contains the transaction status.
 *
 * @category Xi
 * @package  Netvisor
 * @author   Panu Leppäniemi <me@panuleppaniemi.com>
 * @author   Henri Vesala    <henri.vesala@gmail.fi>
 * @author   Petri Koivula   <petri.koivula@iki.fi>
 * @author   Artur Gajewski  <info@arturgajewski.com>
 */
class Netvisor
{
    const SERVICE_INVOICE_ADD = 'salesinvoice';

    const METHOD_ADD  = 'add',
          METHOD_EDIT = 'edit';

    const RESPONSE_STATUS_OK     = 'OK',
          RESPONSE_STATUS_FAILED = 'FAILED';

    const INVALID_DATA_CUSTOMER_NOT_FOUND = 'Customer not found';

    /**
     * @var Config
     */
    private $config;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var Validate
     */
    private $validate;

    /**
     * @var Serializer
     */
    private $serializer;

    /**
     * Initialize with Netvisor::build()
     *
     * @param Client            $client
     * @param Config            $config
     */
    public function __construct(
        Client $client,
        Config $config
    ) {
        $this->client     = $client;
        $this->config     = $config;
        $this->validate   = new Validate();
        $this->serializer = $this->createSerializer();
    }

    /**
     * Builds a default instance of this class.
     *
     * @param  Config           $config
     * @return Netvisor
     */
    public static function build(Config $config)
    {
        return new Netvisor(new Client(), $config);
    }

    /**
     * @param Root              $root
     * @return null|string
     */
    public function sendInvoice(Root $root)
    {
        return $this->request($root, self::SERVICE_INVOICE_ADD);
    }

    /**
     * @param  Root              $root
     * @param  string            $service
     * @param  string            $method
     * @param  string            $id
     * @return null|string
     * @throws NetvisorException
     */
    public function request(Root $root, $service, $method = null, $id = null)
    {
        if (!$this->config->isEnabled()) {
            return null;
        }

        $xml = $this->serializer->serialize($root->getSerializableObject(), 'xml');

        if (!$this->validate->isValid($xml, $root->getDtdPath())) {
            throw new NetvisorException('XML is not valid according to DTD');
        }

        $request = new Request($this->client, $this->config);

        return $request->send($xml, $service, $method, $id);
    }

    /**
     * @return Serializer
     */
    private function createSerializer()
    {
        $builder = SerializerBuilder::create();
        $builder->setPropertyNamingStrategy(new IdenticalPropertyNamingStrategy());

        return $builder->build();
    }
}
