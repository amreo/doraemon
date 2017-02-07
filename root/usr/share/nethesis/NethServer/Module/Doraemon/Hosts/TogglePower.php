<?php
namespace NethServer\Module\Doraemon\Hosts;

use Nethgui\System\PlatformInterface as Validate;

/**
 * Toggle host power status
 *
 * Fires events
 * - doraemon-wake
 * - doraemon-reboot
 * - doraemon-shutdown
 */
class TogglePower extends \Nethgui\Controller\Table\AbstractAction
{

    public function __construct($identifier = NULL)
    {
        if ($identifier !== 'wake' && $identifier !== 'reboot' && $identifier !== 'shutdown') {
            throw new \InvalidArgumentException(sprintf('%s: module identifier must be one of "wake" or "reboot" or "shutdown".', get_class($this)), 1325579395);
        }
        parent::__construct($identifier);
    }

    public function bind(\Nethgui\Controller\RequestInterface $request)
    {
        $this->declareParameter('hostname', Validate::HOSTNAME_SIMPLE);

        parent::bind($request);
        $hostname = \Nethgui\array_end($request->getPath());

        if ( ! $hostname) {
            throw new \Nethgui\Exception\HttpException('Not found', 404, 1322148400);
        }

        $this->parameters['hostname'] = $hostname;
    }

    public function process()
    {
        if ( ! $this->getRequest()->isMutation()) {
            return;
        }

        $this->getPlatform()->signalEvent(sprintf('doraemon-%s@post', $this->getIdentifier()), array($this->parameters['hostname']));
    }

}
