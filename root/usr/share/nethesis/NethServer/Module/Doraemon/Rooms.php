<?php

namespace NethServer\Module\Doraemon;


class Rooms extends \Nethgui\Controller\TableController
{

    public function initialize()
    {
        $columns = array(
            'Key',
            'Actions',
        );

        $this
            ->setTableAdapter($this->getPlatform()->getTableAdapter('rooms', 'room'))
            ->setColumns($columns)
            ->addRowAction(new \NethServer\Module\Doraemon\Rooms\Modify('update'))
            ->addRowAction(new \NethServer\Module\Doraemon\Rooms\Modify('delete'))
            ->addTableAction(new \NethServer\Module\Doraemon\Rooms\Modify('create'))
            ->addTableAction(new \Nethgui\Controller\Table\Help('Help'))
        ;

        parent::initialize();
    }

}
