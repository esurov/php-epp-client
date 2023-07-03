<?php
namespace Metaregistrar\EPP;


class atEppDeleteRequest extends eppDeleteRequest
{
    use atEppCommandTrait;

    function __construct($deleteinfo, atEppExtensionChain $atEppExtensionChain = null) {
        $this->atEppExtensionChain = $atEppExtensionChain;

        parent::__construct($deleteinfo);
        $this->setAtExtensions();
        $this->addSessionId();
    }
}