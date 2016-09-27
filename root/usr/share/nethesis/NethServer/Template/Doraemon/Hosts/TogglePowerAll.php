<?php
$view->requireFlag($view::INSET_DIALOG);

if ($view->getModule()->getIdentifier() == 'shutdown-all') {
    $headerText = $T('Shutdown all hosts');
    $panelText = $T('Proceed with all hosts shutdown?');
} elseif ($view->getModule()->getIdentifier() == 'reboot-all') {
    $headerText = $T('Reboot all hosts');
    $panelText = $T('Proceed with all hosts reboot?');
} else {
    $headerText = $T('Wakeup all hosts');
    $panelText = $T('Proceed with all hosts wakeup?');
}

echo $view->header()->setAttribute('template', $headerText);
// TODO: add a text label here
// echo $view->textLabel()->setAttribute('template', $panelText);
echo $view->buttonList()
    ->insert($view->button('Yes', $view::BUTTON_SUBMIT))
    ->insert($view->button('No', $view::BUTTON_CANCEL)->setAttribute('value', $view['Cancel']))
;
