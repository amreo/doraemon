<?php

namespace NethServer\Module\Doraemon\Rooms;

use Nethgui\System\PlatformInterface as Validate;
use Nethgui\Controller\Table\Modify as Table;


class Modify extends \Nethgui\Controller\Table\Modify
{

    public function initialize()
    {
        $parameterSchema = array(
            // was: Validate::HOSTNAME_FQDN, but we need hostname
            array('Name', Validate::ANYTHING, Table::KEY),
            array('AclRead', Validate::USERNAME_COLLECTION, Table::FIELD, 'AclRead', ','), // ACL
            array('AclWrite', Validate::USERNAME_COLLECTION, Table::FIELD, 'AclWrite', ','), // ACL

//            array('MacAddress', Validate::MACADDRESS, \Nethgui\Controller\Table\Modify::FIELD),
//            array('Role', Validate::ANYTHING, \Nethgui\Controller\Table\Modify::FIELD),
//            array('Role', Validate::ROLES_COLLECTION ??? TODO!!!, \Nethgui\Controller\Table\Modify::FIELD),
        );
        $this->setSchema($parameterSchema);
        parent::initialize();
    }

    public function bind(\Nethgui\Controller\RequestInterface $request)
    {
        parent::bind($request);
        if($request->isMutation()) {
            // save the old values for later usage:
            $this->originalAclRead = $this->getPlatform()->getDatabase('accounts')->getProp($this->parameters['ibay'], 'AclRead');
            $this->originalAclWrite = $this->getPlatform()->getDatabase('accounts')->getProp($this->parameters['ibay'], 'AclWrite');
        }
    }

    public function validate(\Nethgui\Controller\ValidationReportInterface $report)
    {
        if ($this->getIdentifier() === 'delete') {
            $v = $this->createValidator()->platform('room-delete');
            if ( ! $v->evaluate($this->parameters['name'])) {
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
        $this->getPlatform()->signalEvent(sprintf('room-%s &', $actionName));
    }

    public function prepareView(\Nethgui\View\ViewInterface $view)
    {
        parent::prepareView($view);
        $templates = array(
            'create' => 'NethServer\Template\Doraemon\Rooms',
            'update' => 'NethServer\Template\Doraemon\Rooms',
            'delete' => 'Nethgui\Template\Table\Delete',
        );
        $view->setTemplate($templates[$this->getIdentifier()]);


        $owners = array(array('locals', $view->translate('locals_group_label')));
        $subjects = array(array('locals', $view->translate('locals_group_label')));

        foreach ($this->getPlatform()->getDatabase('accounts')->getAll('group') as $keyName => $props) {
            $entry = array($keyName, sprintf("%s (%s)", isset($props['Description']) ? $props['Description'] : $keyName, $keyName));
            $owners[] = $entry;
            $subjects[] = $entry;
        }

        $view['OwningGroupDatasource'] = $owners;

        foreach ($this->getPlatform()->getDatabase('accounts')->getAll('user') as $keyName => $props) {
            $entry = array($keyName, sprintf("%s (%s)", trim($props['FirstName'] . ' ' . $props['LastName']), $keyName));
            $subjects[] = $entry;
        }

        $view['AclSubjects'] = $subjects;

    }

}
