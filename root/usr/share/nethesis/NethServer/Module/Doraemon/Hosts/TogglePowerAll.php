<?php
namespace NethServer\Module\Doraemon\Hosts;

use Nethgui\System\PlatformInterface as Validate;

/**
 * Toggle host power status
 *
 * Fires events
 * - doraemon-wake-all
 * - doraemon-reboot-all
 * - doraemon-shutdown-all
 */
class TogglePowerAll extends \Nethgui\Controller\Table\AbstractAction
{

    public function __construct($identifier = NULL)
    {
        if ($identifier !== 'wake-all' && $identifier !== 'reboot-all' && $identifier !== 'shutdown-all') {
            throw new \InvalidArgumentException(sprintf('%s: module identifier must be one of "wake-all" or "reboot-all" or "shutdown-all".', get_class($this)), 1325579395);
        }
        parent::__construct($identifier);
    }

    public function process()
    {
        if ( ! $this->getRequest()->isMutation()) {
            return;
        }

        $this->getPlatform()->signalEvent(sprintf('doraemon-%s@post', $this->getIdentifier()));
    }

}
