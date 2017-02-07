<?php
$view->requireFlag($view::INSET_DIALOG);

if ($view->getModule()->getIdentifier() == 'shutdown') {
    $headerText = $T('Shutdown host `${0}`');
    $panelText = $T('Proceed with host `${0}` shutdown?');
} elseif ($view->getModule()->getIdentifier() == 'reboot') {
    $headerText = $T('Reboot host `${0}`');
    $panelText = $T('Proceed with host `${0}` reboot?');
} else {
    $headerText = $T('Wakeup host `${0}`');
    $panelText = $T('Proceed with host `${0}` wakeup?');
}

echo $view->panel()
    ->insert($view->header('hostname')->setAttribute('template', $headerText))
    ->insert($view->textLabel('hostname')->setAttribute('template', $panelText))
;

echo $view->buttonList()
    ->insert($view->button('Yes', $view::BUTTON_SUBMIT))
    ->insert($view->button('No', $view::BUTTON_CANCEL)->setAttribute('value', $view['Cancel']))
;
