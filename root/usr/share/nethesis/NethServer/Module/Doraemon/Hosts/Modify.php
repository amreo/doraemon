<?php

namespace NethServer\Module\Doraemon\Hosts;

use Nethgui\System\PlatformInterface as Validate;


class Modify extends \Nethgui\Controller\Table\Modify
{

    public function initialize()
    {
        $parameterSchema = array(
            // was: Validate::HOSTNAME_FQDN, but we need hostname
            array('hostname', Validate::HOSTNAME_SIMPLE, \Nethgui\Controller\Table\Modify::KEY),
            array('MacAddress', Validate::MACADDRESS, \Nethgui\Controller\Table\Modify::FIELD),
            array('Role', Validate::ANYTHING, \Nethgui\Controller\Table\Modify::FIELD),
//            array('Role', Validate::ROLES_COLLECTION ??? TODO!!!, \Nethgui\Controller\Table\Modify::FIELD),
        );
        $this->setSchema($parameterSchema);
        parent::initialize();
    }

    public function validate(\Nethgui\Controller\ValidationReportInterface $report)
    {
        if ($this->getIdentifier() === 'delete') {
            $v = $this->createValidator()->platform('host-delete');
            if ( ! $v->evaluate($this->parameters['hostname'])) {
                $report->addValidationError($this, 'Key', $v);
            }
        }
        parent::validate($report);
    }

    protected function onParametersSaved($parameters)
    {
        $actionName = $this->getIdentifier();
        if ($actionName === 'update') {
            $actionName = 'modify';
        }
        $this->getPlatform()->signalEvent(sprintf('host-%s &', $actionName));
    }

    public function prepareView(\Nethgui\View\ViewInterface $view)
    {
        parent::prepareView($view);
        $templates = array(
            'create' => 'NethServer\Template\Doraemon\Hosts',
            'update' => 'NethServer\Template\Doraemon\Hosts',
            'delete' => 'Nethgui\Template\Table\Delete',
        );
        $view->setTemplate($templates[$this->getIdentifier()]);
    }

}
