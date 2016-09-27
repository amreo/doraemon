<?php

namespace NethServer\Module\Doraemon;


class Hosts extends \Nethgui\Controller\TableController
{

    public function initialize()
    {
        $columns = array(
            'Key',
            'MacAddress',
            'Role',
            'Actions',
        );

        $this
            ->setTableAdapter($this->getPlatform()->getTableAdapter('hosts', 'remote'))
            ->setColumns($columns)
            ->addRowAction(new \NethServer\Module\Doraemon\Hosts\Modify('update'))
            ->addRowAction(new \NethServer\Module\Doraemon\Hosts\TogglePower('wake'))
            ->addRowAction(new \NethServer\Module\Doraemon\Hosts\TogglePower('reboot'))
            ->addRowAction(new \NethServer\Module\Doraemon\Hosts\TogglePower('shutdown'))
            ->addRowAction(new \NethServer\Module\Doraemon\Hosts\Modify('delete'))
            ->addTableAction(new \NethServer\Module\Doraemon\Hosts\Modify('create'))
            ->addTableAction(new \NethServer\Module\Doraemon\Hosts\TogglePowerAll('wake-all'))
            ->addTableAction(new \NethServer\Module\Doraemon\Hosts\TogglePowerAll('reboot-all'))
            ->addTableAction(new \NethServer\Module\Doraemon\Hosts\TogglePowerAll('shutdown-all'))
            ->addTableAction(new \Nethgui\Controller\Table\Help('Help'))
        ;

        parent::initialize();
    }

}
