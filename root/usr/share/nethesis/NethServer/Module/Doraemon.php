<?php
namespace NethServer\Module;

class Doraemon extends \Nethgui\Controller\TabsController
{
    protected function initializeAttributes(\Nethgui\Module\ModuleAttributesInterface $base)
    {
        return \Nethgui\Module\SimpleModuleAttributesProvider::extendModuleAttributes($base, 'Configuration', 50);
    }

    public function initialize()
    {
        parent::initialize();
        $this->loadChildrenDirectory();
    }

}
