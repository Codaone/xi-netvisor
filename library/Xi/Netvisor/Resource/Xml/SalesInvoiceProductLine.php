<?php

namespace Xi\Netvisor\Resource\Xml;

use JMS\Serializer\Annotation as JMS;
use JMS\Serializer\Annotation\XmlRoot;

use Xi\Netvisor\Resource\Xml\Component\AttributeElement;

/** @XmlRoot("SalesInvoiceProductLine") */
class SalesInvoiceProductLine
{
    /**
     * @JMS\Type("Xi\Netvisor\Resource\Xml\Component\AttributeElement")
     */
    private $productIdentifier;
    /**
     * @JMS\Type("string")
     */
    private $productName;
    /**
     * @JMS\Type("Xi\Netvisor\Resource\Xml\Component\AttributeElement")
     */
    private $productUnitPrice;
    /**
     * @JMS\Type("Xi\Netvisor\Resource\Xml\Component\AttributeElement")
     */
    private $productVatPercentage;
    /**
     * @JMS\Type("string")
     */
    private $salesInvoiceProductLineQuantity;

    private $salesInvoiceProductLineFreetext;

    private $accountingAccountSuggestion;

    /**
     * @param string $productIdentifier
     * @param string $productName
     * @param string $productUnitPrice
     * @param string $productVatPercentage
     * @param int    $salesInvoiceProductLineQuantity
     */
    public function __construct(
        $productIdentifier,
        $productName,
        $productUnitPrice,
        $productVat,
        $salesInvoiceProductLineQuantity
    ) {
        $this->productIdentifier = new AttributeElement($productIdentifier, array('type' => 'netvisor')); // TODO: netvisor/customer.
        $this->productName = mb_substr($productName, 0, 50, "UTF-8");
        $this->productUnitPrice = new AttributeElement($productUnitPrice['amount'], array('type' => $productUnitPrice['type']));
        $this->productVatPercentage = new AttributeElement($productVat['percentage'], array('vatcode' => $productVat['code']));
        $this->salesInvoiceProductLineQuantity = $salesInvoiceProductLineQuantity;
    }

    public function setProductVatPercentage($productVatPercentage, $vatcode = 'KOMY'){
        $this->productVatPercentage = new AttributeElement($productVatPercentage, array('vatcode' => $vatcode));
        /*
           Ei saa olla ristiriidassa alv-prosentin kanssa. Sallitut alv-koodit: NONE|KOOS|EUOS|EUUO|EUPO|100|KOMY|EUMY|EUUM|EUPM312|EUPM309|MUUL|EVTO|EVPO|RAMY|RAOS|EVRO

            NONE = Ei alv-käsittelyä 
            KOOS = Kotimaan osto 
            EUOS = EU-osto 
            EUUO = EU:n ulkopuolinen osto 
            EUPO = EU-palveluosto 
            100 = 100% vähennettävä vero 
            KOMY = Kotimaan myynti 
            EUMY = EU-myynti 
            EUUM = EU:n ulkopuolinen myynt
        */
    }

    public function setProductUnitPrice($amount, $type){
        $this->productUnitPrice = new AttributeElement($amount, array('type' => $type));
    }
    public function getProductUnitPrice()
    {
        return $this->productUnitPrice->getValue();
    }
    public function getProductName()
    {
        return $this->productName;
    }
    public function setProductName($productName){
        $this->productName = mb_substr($productName, 0, 50,"UTF-8");
    }
    public function setProductLineFreetext($text){
        $this->salesInvoiceProductLineFreetext = mb_substr($text, 0, 200,"UTF-8");
    }

    public function setProductIdentifier($productIdentifier){
        $this->productIdentifier = new AttributeElement($productIdentifier, array('type' => 'netvisor')); // TODO: netvisor/customer.
    }
    public function setAccountinAccountSuggestion($account){
        $this->accountingAccountSuggestion = $account;
    }
    public function getSalesInvoiceProductLineQuantity()
    {
        return $this->salesInvoiceProductLineQuantity;
    }
    public function setSalesInvoiceProductLineQuantity($salesInvoiceProductLineQuantity)
    {
        $this->salesInvoiceProductLineQuantity = $salesInvoiceProductLineQuantity;
    }
}
